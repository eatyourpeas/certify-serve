import io
import csv
import base64
import zipfile
import importlib
import inspect
import smtplib
from email.message import EmailMessage
from typing import List, Dict, Tuple, Optional

from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.openapi.utils import get_openapi

app = FastAPI(
    title="Certify Attendance Server",
    docs_url="/swagger",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


def _clear_examples_in_schema(schema: dict):
    """Recursively set string examples to empty to avoid Swagger placeholders."""
    if not isinstance(schema, dict):
        return
    t = schema.get("type")
    if t == "string":
        schema["example"] = ""
    # recurse into properties and items
    if "properties" in schema and isinstance(schema["properties"], dict):
        for prop in schema["properties"].values():
            _clear_examples_in_schema(prop)
    if "items" in schema:
        _clear_examples_in_schema(schema["items"])


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(title=app.title, version="1.0.0", routes=app.routes)
    # clear examples in component schemas
    components = openapi_schema.get("components", {})
    schemas = components.get("schemas", {})
    for name, sch in schemas.items():
        _clear_examples_in_schema(sch)

    # also clear examples in path parameters/request bodies
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
    """Try to find a reasonable generator callable in the certify_attendance package.
    This is tolerant to a few common function/class names; if not found, raises RuntimeError.
    """
    module = importlib.import_module("certify_attendance")
    # common function names
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

    # search for any callable with pdf in the name
    for name, obj in vars(module).items():
        if callable(obj) and "pdf" in name.lower():
            return obj

    # look for a class with a generate-like method
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
    """Call the discovered generator trying a few common signatures.
    Expected to return an iterable of (email, pdf_bytes) or list of dicts with those keys.
    """
    # Try common kwargs
    try:
        result = generator(attendees, title=title, date=date, logo=logo_bytes)
        return _normalize_generator_result(result)
    except TypeError:
        pass

    # Try positional
    try:
        result = generator(attendees, title, date, logo_bytes)
        return _normalize_generator_result(result)
    except TypeError:
        pass

    # Try without logo
    try:
        result = generator(attendees, title, date)
        return _normalize_generator_result(result)
    except Exception as exc:
        raise RuntimeError(f"Generator call failed: {exc}")


def _normalize_generator_result(result) -> List[Tuple[str, bytes]]:
    """Normalize various expected return types into List[(email, pdf_bytes)]."""
    out = []
    if result is None:
        return out
    # list of tuples
    if isinstance(result, (list, tuple)):
        for item in result:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                email, pdf = item[0], item[1]
                out.append((email, pdf))
            elif isinstance(item, dict):
                # expect keys like 'email' and 'pdf' or 'pdf_bytes'
                email = item.get("email") or item.get("attendee_email")
                pdf = item.get("pdf") or item.get("pdf_bytes") or item.get("content")
                if email and pdf:
                    out.append((email, pdf))
    return out


def _parse_csv(file_bytes: bytes) -> List[Dict]:
    text = file_bytes.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    # normalize headers to lowercase and strip
    rows = []
    for r in reader:
        normalized = {k.strip().lower(): v.strip() for k, v in r.items() if k}
        rows.append(normalized)
    # map expected fields
    attendees = []
    for r in rows:
        keys = list(r.keys())
        # heuristics
        first_key = next((k for k in keys if "first" in k), None)
        last_key = next(
            (k for k in keys if "surname" in k or "last" in k or "family" in k), None
        )
        email_key = next((k for k in keys if "email" in k), None)
        if not (first_key and last_key and email_key):
            raise HTTPException(
                status_code=422,
                detail=f"CSV missing expected columns (found: {keys}). Need first, surname/last and email columns.",
            )
        attendees.append(
            {
                "first_name": r.get(first_key, ""),
                "surname": r.get(last_key, ""),
                "email": r.get(email_key, ""),
            }
        )
    return attendees


def _create_zip(pdf_items: List[Tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for email, pdf in pdf_items:
            # sanitize filename
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
    if _GENERATOR is None:
        raise HTTPException(
            status_code=500,
            detail="certify_attendance generator not available on startup",
        )
    logo_bytes = await (logo.read() if logo else b"")
    attendees = [{"first_name": first_name, "surname": surname, "email": email}]
    pdf_items = _call_generator(
        _GENERATOR, attendees, conference_title, conference_date, logo_bytes or None
    )
    if review:
        # return a zip for the single item as stream
        zip_bytes = _create_zip(pdf_items)
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
    # default: return zip for download
    zip_bytes = _create_zip(pdf_items)
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
    if _GENERATOR is None:
        raise HTTPException(
            status_code=500,
            detail="certify_attendance generator not available on startup",
        )
    csv_bytes = await csv_file.read()
    attendees = _parse_csv(csv_bytes)
    logo_bytes = await (logo.read() if logo else b"")
    pdf_items = _call_generator(
        _GENERATOR, attendees, conference_title, conference_date, logo_bytes or None
    )
    if review:
        zip_bytes = _create_zip(pdf_items)
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
    zip_bytes = _create_zip(pdf_items)
    return StreamingResponse(
        io.BytesIO(zip_bytes),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=certificates.zip"},
    )
