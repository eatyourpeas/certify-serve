import io
import csv
import logging
import zipfile
import importlib
import inspect
import smtplib
import os
from email.message import EmailMessage
from typing import List, Dict, Tuple, Optional
import httpx
import tempfile

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.openapi.utils import get_openapi


app = FastAPI(
    title="Certify Attendance Server",
    docs_url="/swagger",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


def _clear_examples_in_schema(schema: dict):
    if not isinstance(schema, dict):
        return
    t = schema.get("type")
    if t == "string":
        schema["example"] = ""
    if "properties" in schema and isinstance(schema["properties"], dict):
        for prop in schema["properties"].values():
            _clear_examples_in_schema(prop)
    if "items" in schema:
        _clear_examples_in_schema(schema["items"])


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(title=app.title, version="1.0.0", routes=app.routes)
    components = openapi_schema.get("components", {})
    schemas = components.get("schemas", {})
    for name, sch in schemas.items():
        _clear_examples_in_schema(sch)

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "schema" and isinstance(v, dict):
                    _clear_examples_in_schema(v)
                else:
                    walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(openapi_schema.get("paths", {}))
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


def _find_generator():
    module = importlib.import_module("certify_attendance")
    candidates = [
        "generate_certificates",
        "generate_pdfs",
        "render_certificates",
        "generate",
        "create_certificates",
    ]
    for name in candidates:
        if hasattr(module, name) and callable(getattr(module, name)):
            return getattr(module, name)
    for name, obj in vars(module).items():
        if callable(obj) and "pdf" in name.lower():
            return obj
    for name, obj in vars(module).items():
        if inspect.isclass(obj):
            for m in ("generate", "create", "render"):
                if hasattr(obj, m):
                    instance = obj()
                    return getattr(instance, m)
    raise RuntimeError(
        "No suitable generator found in certify_attendance. Please ensure the package exports a generator function."
    )


def _call_generator(
    generator,
    attendees: List[Dict],
    title: str,
    date: str,
    logo_bytes: Optional[bytes] = None,
):
    try:
        result = generator(attendees, title=title, date=date, logo=logo_bytes)
        return _normalize_generator_result(result)
    except TypeError:
        pass
    try:
        result = generator(attendees, title, date, logo_bytes)
        return _normalize_generator_result(result)
    except TypeError:
        pass
    try:
        result = generator(attendees, title, date)
        return _normalize_generator_result(result)
    except Exception as exc:
        raise RuntimeError(f"Generator call failed: {exc}")


def _normalize_generator_result(result) -> List[Tuple[str, bytes]]:
    out = []
    if result is None:
        return out
    if isinstance(result, (list, tuple)):
        for item in result:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                email, pdf = item[0], item[1]
                out.append((email, pdf))
            elif isinstance(item, dict):
                email = item.get("email") or item.get("attendee_email")
                pdf = item.get("pdf") or item.get("pdf_bytes") or item.get("content")
                if email and pdf:
                    out.append((email, pdf))
    return out


def _parse_csv(file_bytes: bytes) -> List[Dict]:
    text = file_bytes.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for r in reader:
        normalized = {k.strip().lower(): v.strip() for k, v in r.items() if k}
        rows.append(normalized)
    attendees = []
    for r in rows:
        keys = list(r.keys())
        # support 'name' + 'attendee_email' CSV used by tests
        if "name" in r and ("attendee_email" in r or "email" in r):
            name = r.get("name", "")
            parts = name.split()
            first = parts[0] if parts else ""
            last = " ".join(parts[1:]) if len(parts) > 1 else ""
            email_val = r.get("attendee_email") or r.get("email") or ""
            attendees.append({"first_name": first, "surname": last, "email": email_val})
            continue

        # heuristics for first/last/email style headers
        first_key = next((k for k in keys if "first" in k), None)
        last_key = next(
            (k for k in keys if "surname" in k or "last" in k or "family" in k), None
        )
        email_key = next((k for k in keys if "email" in k), None)
        attendees.append(
            {
                "first_name": r.get(first_key, "") if first_key else "",
                "surname": r.get(last_key, "") if last_key else "",
                "email": r.get(email_key, "") if email_key else "",
            }
        )
    return attendees


def _create_zip(pdf_items: List[Tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for email, pdf in pdf_items:
            name = email.replace("@", "_at_").replace(".", "_")
            zf.writestr(f"{name}.pdf", pdf)
    buf.seek(0)
    return buf.read()


def _send_emails(
    smtp_host: str,
    smtp_port: int,
    username: Optional[str],
    password: Optional[str],
    from_name: str,
    from_email: str,
    subject: str,
    body: str,
    pdf_items: List[Tuple[str, bytes]],
):
    backend = os.environ.get("SMTP_BACKEND")
    logger = logging.getLogger(__name__)
    if backend == "console":
        sent = 0
        for to_email, pdf in pdf_items:
            print(
                f"TO: {to_email}\nSUBJECT: {subject}\n{body}\n[PDF {len(pdf)} bytes]\n"
            )
            logger.info("Sent console email to %s", to_email)
            sent += 1
        return sent

    use_ssl = smtp_port == 465
    if use_ssl:
        server = smtplib.SMTP_SSL(smtp_host, smtp_port)
    else:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
    try:
        if username and password:
            server.login(username, password)
        for to_email, pdf in pdf_items:
            msg = EmailMessage()
            msg["From"] = f"{from_name} <{from_email}>"
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.set_content(body)
            msg.add_attachment(
                pdf, maintype="application", subtype="pdf", filename="certificate.pdf"
            )
            server.send_message(msg)
    finally:
        server.quit()


# compatibility helpers expected by tests
def create_certificate(
    first_name: str,
    surname: str,
    email: str,
    conference_title: str,
    conference_date: str,
    output_path: Optional[str] = None,
    logo_bytes: Optional[bytes] = None,
):
    if _GENERATOR is None:
        raise RuntimeError("certify_attendance generator not available")
    attendees = [{"first_name": first_name, "surname": surname, "email": email}]
    pdf_items = _call_generator(
        _GENERATOR, attendees, conference_title, conference_date, logo_bytes or None
    )
    if not pdf_items:
        return None
    _, pdf = pdf_items[0]
    if output_path:
        with open(output_path, "wb") as fh:
            fh.write(pdf)
        return output_path
    return pdf


def generate_batch(
    attendees: List[Dict],
    conference_title: str,
    conference_date: str,
    logo_bytes: Optional[bytes] = None,
):
    if _GENERATOR is None:
        raise RuntimeError("certify_attendance generator not available")
    pdf_items = _call_generator(
        _GENERATOR, attendees, conference_title, conference_date, logo_bytes or None
    )
    generated = []
    email_jobs = []
    for email, pdf in pdf_items:
        name = email.split("@")[0]
        filename = email.replace("@", "_at_").replace(".", "_") + ".pdf"
        generated.append({"name": name, "filename": filename, "pdf_bytes": pdf})
        email_jobs.append({"recipient": email, "pdf_bytes": pdf, "filename": filename})
    zip_bytes = _create_zip(pdf_items)
    return {"generated": generated, "zip": zip_bytes, "email_jobs": email_jobs}


# cache generator lookup
_GENERATOR = None


@app.on_event("startup")
def startup_event():
    global _GENERATOR
    try:
        _GENERATOR = _find_generator()
    except Exception:
        _GENERATOR = None


@app.post("/generate")
async def generate_single(
    first_name: str = Form(...),
    surname: str = Form(...),
    email: str = Form(...),
    conference_title: str = Form(...),
    conference_date: str = Form(...),
    logo: Optional[UploadFile] = File(None),
    review: bool = Form(True),
    send: bool = Form(False),
    smtp_host: Optional[str] = Form(None),
    smtp_port: Optional[int] = Form(None),
    smtp_username: Optional[str] = Form(None),
    smtp_password: Optional[str] = Form(None),
    from_name: str = Form("Conference Team"),
    from_email: str = Form("noreply@example.com"),
    subject: str = Form("Your attendance certificate"),
    body: str = Form("Please find your attendance certificate attached."),
):
    logo_bytes = await logo.read() if logo else b""

    # Prefer the compatibility helper `create_certificate` (tests monkeypatch it)
    if review:
        # ask helper to write to a temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            out = create_certificate(
                first_name,
                surname,
                email,
                conference_title,
                conference_date,
                output_path=tmp.name,
                logo_bytes=logo_bytes or None,
            )
            tmp_path = out
        with open(tmp_path, "rb") as fh:
            pdf = fh.read()
        zip_bytes = _create_zip([(email, pdf)])
        return StreamingResponse(
            io.BytesIO(zip_bytes),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=certificates.zip"},
        )

    if send:
        if not smtp_host or not smtp_port:
            raise HTTPException(
                status_code=422, detail="SMTP host and port required to send emails"
            )
        out = create_certificate(
            first_name,
            surname,
            email,
            conference_title,
            conference_date,
            logo_bytes=logo_bytes or None,
        )
        if isinstance(out, str):
            with open(out, "rb") as fh:
                pdf = fh.read()
        else:
            pdf = out
        pdf_items = [(email, pdf)]
        _send_emails(
            smtp_host,
            int(smtp_port),
            smtp_username,
            smtp_password,
            from_name,
            from_email,
            subject,
            body,
            pdf_items,
        )
        return {"status": "sent", "count": len(pdf_items)}

    # default: generate and return zip
    out = create_certificate(
        first_name,
        surname,
        email,
        conference_title,
        conference_date,
        logo_bytes=logo_bytes or None,
    )
    if isinstance(out, str):
        with open(out, "rb") as fh:
            pdf = fh.read()
    else:
        pdf = out
    zip_bytes = _create_zip([(email, pdf)])
    return StreamingResponse(
        io.BytesIO(zip_bytes),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=certificates.zip"},
    )


@app.post("/generate/csv")
async def generate_csv(
    csv_file: UploadFile = File(...),
    conference_title: str = Form(...),
    conference_date: str = Form(...),
    logo: Optional[UploadFile] = File(None),
    review: bool = Form(True),
    send: bool = Form(False),
    smtp_host: Optional[str] = Form(None),
    smtp_port: Optional[int] = Form(None),
    smtp_username: Optional[str] = Form(None),
    smtp_password: Optional[str] = Form(None),
    from_name: str = Form("Conference Team"),
    from_email: str = Form("noreply@example.com"),
    subject: str = Form("Your attendance certificate"),
    body: str = Form("Please find your attendance certificate attached."),
):
    csv_bytes = await csv_file.read()
    attendees = _parse_csv(csv_bytes)
    logo_bytes = await logo.read() if logo else b""
    # Prefer compatibility helper `generate_batch` (tests monkeypatch it)
    try:
        result = generate_batch(
            attendees, conference_title, conference_date, logo_bytes or None
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Batch generation failed: {exc}")

    if review:
        return StreamingResponse(
            io.BytesIO(result.get("zip", b"")),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=certificates.zip"},
        )
    if send:
        if not smtp_host or not smtp_port:
            raise HTTPException(
                status_code=422, detail="SMTP host and port required to send emails"
            )
        # assemble pdf_items from result
        email_jobs = result.get("email_jobs", [])
        pdf_items = [(job.get("recipient"), job.get("pdf_bytes")) for job in email_jobs]
        _send_emails(
            smtp_host,
            int(smtp_port),
            smtp_username,
            smtp_password,
            from_name,
            from_email,
            subject,
            body,
            pdf_items,
        )
        return {"status": "sent", "count": len(pdf_items)}

    return StreamingResponse(
        io.BytesIO(result.get("zip", b"")),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=certificates.zip"},
    )


@app.post("/generate/eventbrite")
async def generate_eventbrite(
    event_id: str = Form(...),
    eventbrite_token: str = Form(...),
    review: bool = Form(True),
):
    base = f"https://www.eventbriteapi.com/v3/events/{event_id}"
    async with httpx.AsyncClient() as client:
        ev = await client.get(base + "/")
        ev.raise_for_status()
        evj = ev.json()
        title = evj.get("name", {}).get("text", "Event")
        date = evj.get("start", {}).get("local", "")
        att = await client.get(base + "/attendees/", params={})
        att.raise_for_status()
        attj = att.json()
        attendees = []
        for a in attj.get("attendees", []):
            profile = a.get("profile", {})
            attendees.append(
                {
                    "first_name": profile.get("first_name", ""),
                    "surname": profile.get("last_name", ""),
                    "email": profile.get("email", ""),
                }
            )
    try:
        result = generate_batch(attendees, title, date)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Batch generation failed: {exc}")
    if review:
        return StreamingResponse(
            io.BytesIO(result.get("zip", b"")),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=certificates.zip"},
        )
    return {"status": "ok", "count": len(result.get("generated", []))}
