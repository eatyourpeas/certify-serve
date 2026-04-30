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

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI(
    title="Certify Attendance Server",
    docs_url="/swagger",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Add CORS middleware to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for the frontend
# Use absolute path based on current working directory to work in Docker
site_dir = os.path.join(os.getcwd(), "site")
app.mount("/site", StaticFiles(directory=site_dir), name="site")


# Inject environment variables into HTML
def get_env_vars():
    return {
        "eventbriteToken": os.environ.get("EVENTBRITE_TOKEN", ""),
        "smtpHost": os.environ.get("SMTP_HOST", ""),
        "smtpPort": os.environ.get("SMTP_PORT", ""),
        "smtpUsername": os.environ.get("SMTP_USERNAME", ""),
        "smtpPassword": os.environ.get("SMTP_PASSWORD", ""),
        "fromName": os.environ.get("FROM_NAME", "Conference Team"),
        "fromEmail": os.environ.get("FROM_EMAIL", "noreply@example.com"),
    }


@app.get("/")
async def serve_frontend():
    html_path = os.path.join(site_dir, "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r") as f:
            html = f.read()
        env_vars = get_env_vars()
        # Inject environment variables as data attributes using kebab-case names
        # so they map correctly to JS dataset.camelCase access.
        import re

        def _to_kebab(s):
            return re.sub(r"(?<!^)(?=[A-Z])", "-", s).lower()

        data_attrs = " ".join(
            f'data-{_to_kebab(key)}="{value}"' for key, value in env_vars.items()
        )
        html = html.replace('<html lang="en">', f'<html lang="en" {data_attrs}>')
        return FileResponse(
            html_path, media_type="text/html", headers={"Content-Disposition": "inline"}
        )
    return FileResponse(html_path)


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

# cache generator lookup (declare early so linters/editors don't flag usage)
_GENERATOR: Optional[callable] = None


def _find_generator():
    module = None
    import_errors = []
    for module_name in ("certify_attendance", "certify"):
        try:
            module = importlib.import_module(module_name)
            break
        except Exception as exc:
            import_errors.append(f"{module_name}: {exc}")

    if module is None:
        raise RuntimeError(
            "Could not import certificate package. Tried certify_attendance and certify. "
            + "; ".join(import_errors)
        )

    # Compatibility path for published 'certify-attendance' package exposing module 'certify'.
    if module.__name__ == "certify" and hasattr(module, "create_certificate"):
        return _call_certify_create_certificate

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


def _call_certify_create_certificate(
    attendees: List[Dict],
    title: str,
    date: str,
    subtitle: Optional[str] = None,
    location: Optional[str] = None,
    logo: Optional[bytes] = None,
):
    certify_module = importlib.import_module("certify")
    create_certificate = getattr(certify_module, "create_certificate")
    outputs: List[Tuple[str, bytes]] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        logo_path = None
        if logo:
            logo_path = os.path.join(tmpdir, "logo.png")
            # Normalise logos to a centered square canvas so placement is consistent.
            try:
                from PIL import Image

                with Image.open(io.BytesIO(logo)) as src:
                    src_rgba = src.convert("RGBA")
                    canvas_size = max(600, src_rgba.width, src_rgba.height)
                    canvas = Image.new(
                        "RGBA", (canvas_size, canvas_size), (255, 255, 255, 0)
                    )
                    scale = min(
                        (canvas_size * 0.7) / max(src_rgba.width, 1),
                        (canvas_size * 0.7) / max(src_rgba.height, 1),
                        1,
                    )
                    resized = src_rgba.resize(
                        (
                            max(1, int(src_rgba.width * scale)),
                            max(1, int(src_rgba.height * scale)),
                        ),
                        Image.Resampling.LANCZOS,
                    )
                    x = (canvas_size - resized.width) // 2
                    y = (canvas_size - resized.height) // 2
                    canvas.paste(resized, (x, y), resized)
                    canvas.save(logo_path, format="PNG")
            except Exception:
                with open(logo_path, "wb") as f:
                    f.write(logo)

        for idx, attendee in enumerate(attendees):
            first = attendee.get("first_name", "")
            surname = attendee.get("surname", "")
            full_name = f"{first} {surname}".strip() or attendee.get("name", "Attendee")
            email = attendee.get("email", f"attendee_{idx}@example.com")
            out_path = os.path.join(tmpdir, f"certificate_{idx}.pdf")

            kwargs = {
                "attendee_name": full_name,
                "course_title": title,
                "location": location or "",
                "date": date,
                "subtitle": subtitle or "",
                "output_path": out_path,
                # Prevent certify package default host text from leaking into the certificate.
                "host_hospital": location or "",
                "host_trust": "",
            }
            if logo_path:
                kwargs["organiser_logo"] = logo_path

            create_certificate(**kwargs)
            with open(out_path, "rb") as fh:
                outputs.append((email, fh.read()))

    return outputs


def _call_generator(
    generator,
    attendees: List[Dict],
    title: str,
    date: str,
    subtitle: Optional[str] = None,
    location: Optional[str] = None,
    logo_bytes: Optional[bytes] = None,
):
    try:
        result = generator(
            attendees,
            title=title,
            date=date,
            subtitle=subtitle,
            location=location,
            logo=logo_bytes,
        )
        return _normalize_generator_result(result)
    except TypeError:
        pass
    try:
        result = generator(attendees, title, date, subtitle, location, logo_bytes)
        return _normalize_generator_result(result)
    except TypeError:
        pass
    try:
        result = generator(attendees, title, date, subtitle, logo_bytes)
        return _normalize_generator_result(result)
    except TypeError:
        pass
    try:
        result = generator(attendees, title, date, subtitle)
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
    subtitle: Optional[str] = None,
    location: Optional[str] = None,
    output_path: Optional[str] = None,
    logo_bytes: Optional[bytes] = None,
):
    if _GENERATOR is None:
        raise RuntimeError("certify_attendance generator not available")
    attendees = [{"first_name": first_name, "surname": surname, "email": email}]
    pdf_items = _call_generator(
        _GENERATOR,
        attendees,
        conference_title,
        conference_date,
        subtitle,
        location,
        logo_bytes or None,
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
    subtitle: Optional[str] = None,
    location: Optional[str] = None,
    logo_bytes: Optional[bytes] = None,
):
    if _GENERATOR is None:
        raise RuntimeError("certify_attendance generator not available")
    pdf_items = _call_generator(
        _GENERATOR,
        attendees,
        conference_title,
        conference_date,
        subtitle,
        location,
        logo_bytes or None,
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


_STATUS_FILTERS = {"attended", "registered", "declined", "waitlisted"}
_STATUS_TO_EVENTBRITE_PARAM = {
    "attended": "attending",
    "registered": "attending",
    "declined": "not_attending",
    "waitlisted": "waitlist",
}


def _matches_requested_status(attendee: Dict, requested_status: Optional[str]) -> bool:
    if not requested_status:
        return True
    status_value = str(
        attendee.get("status")
        or attendee.get("attendee_status")
        or attendee.get("attendance_status")
        or ""
    ).lower()
    checked_in = bool(attendee.get("checked_in"))

    if requested_status == "attended":
        return checked_in or status_value in {"attended", "attending", "checked_in"}
    if requested_status == "registered":
        return status_value in {"registered", "attending", "attended"}
    if requested_status == "declined":
        return status_value in {"declined", "not_attending"}
    if requested_status == "waitlisted":
        return status_value in {"waitlisted", "waitlist"}
    return True


async def _fetch_eventbrite_attendees(
    event_id: str,
    eventbrite_token: str,
    requested_status: Optional[str] = None,
) -> List[Dict]:
    base = f"https://www.eventbriteapi.com/v3/events/{event_id}"
    headers = {"Authorization": f"Bearer {eventbrite_token}"}
    api_status = (
        _STATUS_TO_EVENTBRITE_PARAM.get(requested_status) if requested_status else None
    )
    api_status_supported = True

    async with httpx.AsyncClient() as client:
        next_continuation = None
        attendees = []
        while True:
            params = {}
            if api_status and api_status_supported:
                params["status"] = api_status
            if next_continuation:
                params["continuation"] = next_continuation

            att = await client.get(base + "/attendees/", params=params, headers=headers)
            try:
                att.raise_for_status()
            except httpx.HTTPStatusError as exc:
                # Some Eventbrite events reject status filtering. Retry once without status.
                if params.get("status") and exc.response.status_code == 400:
                    api_status_supported = False
                    next_continuation = None
                    attendees = []
                    continue
                raise HTTPException(
                    status_code=502,
                    detail=f"Eventbrite attendees request failed ({exc.response.status_code}): {exc.response.text}",
                )

            attj = att.json()
            for a in attj.get("attendees", []):
                if requested_status and not _matches_requested_status(
                    a, requested_status
                ):
                    continue
                attendees.append(a)

            pagination = attj.get("pagination", {})
            if not pagination.get("has_more_items"):
                break
            next_continuation = pagination.get("continuation")
            if not next_continuation:
                break

    return attendees


async def _fetch_eventbrite_event_metadata(event_id: str, eventbrite_token: str):
    base = f"https://www.eventbriteapi.com/v3/events/{event_id}"
    headers = {"Authorization": f"Bearer {eventbrite_token}"}
    async with httpx.AsyncClient() as client:
        ev = await client.get(base + "/", headers=headers)
        ev.raise_for_status()
        evj = ev.json()
        location = ""
        try:
            venue = await client.get(base + "/venue/", headers=headers)
            if venue.status_code < 400:
                vj = venue.json()
                location = (
                    vj.get("address", {}).get("localized_address_display")
                    or vj.get("name")
                    or ""
                )
        except Exception:
            location = ""
    return {
        "event_id": event_id,
        "conference_title": evj.get("name", {}).get("text", ""),
        "conference_date": evj.get("start", {}).get("local", ""),
        "subtitle": evj.get("summary") or evj.get("description", {}).get("text"),
        "location": location,
    }


@app.on_event("startup")
def startup_event():
    global _GENERATOR
    try:
        _GENERATOR = _find_generator()
    except Exception:
        _GENERATOR = None


@app.api_route("/generate/eventbrite/preview", methods=["GET", "POST"])
@app.api_route("/generate/eventbrite/preview/", methods=["GET", "POST"])
async def preview_eventbrite_event(
    request: Request,
    event_id: Optional[str] = None,
    eventbrite_token: Optional[str] = None,
):
    # Accept either query params (GET) or form body (POST).
    if not event_id:
        event_id = request.query_params.get("event_id")
    if not eventbrite_token:
        eventbrite_token = request.query_params.get("eventbrite_token")

    if request.method == "POST" and (not event_id or not eventbrite_token):
        form = await request.form()
        event_id = event_id or form.get("event_id")
        eventbrite_token = eventbrite_token or form.get("eventbrite_token")

    eventbrite_token = eventbrite_token or os.environ.get("EVENTBRITE_TOKEN", "")

    if not event_id or not eventbrite_token:
        raise HTTPException(
            status_code=422,
            detail="event_id and eventbrite_token are required (set EVENTBRITE_TOKEN env var or supply in the form)",
        )

    try:
        return await _fetch_eventbrite_event_metadata(event_id, eventbrite_token)
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch Eventbrite event metadata: {exc}"
        )


@app.api_route("/generate/eventbrite/attendees", methods=["GET", "POST"])
@app.api_route("/generate/eventbrite/attendees/", methods=["GET", "POST"])
async def list_eventbrite_attendees(
    request: Request,
    event_id: Optional[str] = None,
    eventbrite_token: Optional[str] = None,
    status: Optional[str] = None,
):
    if not event_id:
        event_id = request.query_params.get("event_id")
    if not eventbrite_token:
        eventbrite_token = request.query_params.get("eventbrite_token")
    if not status:
        status = request.query_params.get("status")

    if request.method == "POST" and (not event_id or not eventbrite_token):
        form = await request.form()
        event_id = event_id or form.get("event_id")
        eventbrite_token = eventbrite_token or form.get("eventbrite_token")
        status = status or form.get("status")

    eventbrite_token = eventbrite_token or os.environ.get("EVENTBRITE_TOKEN", "")

    if not event_id or not eventbrite_token:
        raise HTTPException(
            status_code=422,
            detail="event_id and eventbrite_token are required (set EVENTBRITE_TOKEN env var or supply in the form)",
        )

    requested_status = status.lower() if status else None
    if requested_status and requested_status not in _STATUS_FILTERS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported status filter '{status}'. Supported values: attended, registered, declined, waitlisted",
        )

    metadata = await _fetch_eventbrite_event_metadata(event_id, eventbrite_token)
    attendees = await _fetch_eventbrite_attendees(
        event_id, eventbrite_token, requested_status
    )

    rows = []
    for a in attendees:
        profile = a.get("profile", {})
        rows.append(
            {
                "first_name": profile.get("first_name", ""),
                "surname": profile.get("last_name", ""),
                "email": profile.get("email", ""),
                "title": profile.get("honorific", ""),
                "status": a.get("status") or "",
                "checked_in": bool(a.get("checked_in")),
            }
        )

    return {"metadata": metadata, "attendees": rows, "count": len(rows)}


@app.post("/generate")
async def generate_single(
    first_name: str = Form(...),
    surname: str = Form(...),
    email: str = Form(...),
    conference_title: str = Form(...),
    conference_date: str = Form(...),
    subtitle: Optional[str] = Form(None),
    location: Optional[str] = Form(None),
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
                subtitle=subtitle,
                location=location,
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
            subtitle=subtitle,
            location=location,
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
        subtitle=subtitle,
        location=location,
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
    subtitle: Optional[str] = Form(None),
    location: Optional[str] = Form(None),
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
            attendees,
            conference_title,
            conference_date,
            subtitle,
            location,
            logo_bytes or None,
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
    eventbrite_token: Optional[str] = Form(None),
    conference_title: Optional[str] = Form(None),
    conference_date: Optional[str] = Form(None),
    subtitle: Optional[str] = Form(None),
    location: Optional[str] = Form(None),
    selected_emails: Optional[str] = Form(None),
    logo: Optional[UploadFile] = File(None),
    review: bool = Form(True),
    send: bool = Form(False),
    status: Optional[str] = Form(None),
    greeting_type: str = Form("simple"),
    smtp_host: Optional[str] = Form(None),
    smtp_port: Optional[int] = Form(None),
    smtp_username: Optional[str] = Form(None),
    smtp_password: Optional[str] = Form(None),
    from_name: str = Form("Conference Team"),
    from_email: str = Form("noreply@example.com"),
    subject: str = Form("Your attendance certificate"),
    body: str = Form("Please find your attendance certificate attached."),
):
    eventbrite_token = (eventbrite_token or "").strip() or os.environ.get(
        "EVENTBRITE_TOKEN", ""
    )
    if not eventbrite_token:
        raise HTTPException(
            status_code=422,
            detail="eventbrite_token is required (set EVENTBRITE_TOKEN env var or supply in the form)",
        )
    smtp_host = smtp_host or os.environ.get("SMTP_HOST") or None
    _smtp_port_raw = smtp_port or os.environ.get("SMTP_PORT") or None
    smtp_port = int(_smtp_port_raw) if _smtp_port_raw else None
    smtp_username = smtp_username or os.environ.get("SMTP_USERNAME") or None
    smtp_password = smtp_password or os.environ.get("SMTP_PASSWORD") or None
    logo_bytes = await logo.read() if logo else b""

    metadata = await _fetch_eventbrite_event_metadata(event_id, eventbrite_token)
    event_title = metadata.get("conference_title", "")
    event_date = metadata.get("conference_date", "")
    event_subtitle = metadata.get("subtitle")
    event_location = metadata.get("location")

    resolved_title = conference_title or event_title or "Event"
    resolved_date = conference_date or event_date or ""
    resolved_subtitle = subtitle if subtitle else event_subtitle
    resolved_location = (location or "").strip() or (event_location or "")

    requested_status = status.lower() if status else None
    if requested_status and requested_status not in _STATUS_FILTERS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported status filter '{status}'. Supported values: attended, registered, declined, waitlisted",
        )

    selected_email_set = None
    if selected_emails:
        try:
            import json

            parsed = json.loads(selected_emails)
            if isinstance(parsed, list):
                selected_email_set = {
                    str(x).strip().lower() for x in parsed if str(x).strip()
                }
        except Exception as exc:
            raise HTTPException(
                status_code=422, detail=f"Invalid selected_emails payload: {exc}"
            )

    raw_attendees = await _fetch_eventbrite_attendees(
        event_id, eventbrite_token, requested_status
    )

    attendees = []
    attendee_profiles = []
    for a in raw_attendees:
        profile = a.get("profile", {})
        attendee_email = (profile.get("email") or "").strip().lower()
        if selected_email_set is not None and attendee_email not in selected_email_set:
            continue
        attendee_data = {
            "first_name": profile.get("first_name", ""),
            "surname": profile.get("last_name", ""),
            "email": profile.get("email", ""),
        }
        attendees.append(attendee_data)
        honorific = profile.get("honorific", "")
        attendee_profiles.append(
            {
                "first_name": attendee_data["first_name"],
                "surname": attendee_data["surname"],
                "email": attendee_data["email"],
                "title": honorific,
            }
        )

    if not attendees:
        raise HTTPException(
            status_code=422, detail="No attendees matched the current selection"
        )
    try:
        result = generate_batch(
            attendees,
            resolved_title,
            resolved_date,
            resolved_subtitle,
            resolved_location,
            logo_bytes or None,
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
                status_code=422,
                detail="SMTP host and port required to send emails (set SMTP_HOST and SMTP_PORT env vars or supply in the form)",
            )
        # Send personalized emails with interpolated attendee data
        email_jobs = result.get("email_jobs", [])
        sent_emails = []
        failed_emails = []
        for i, job in enumerate(email_jobs):
            recipient = job.get("recipient")
            pdf_bytes = job.get("pdf_bytes")
            profile = attendee_profiles[i] if i < len(attendee_profiles) else {}

            # Interpolate attendee data into email body based on greeting_type
            personalized_body = body
            if greeting_type == "personalized":
                # Apply all placeholders for full personalization
                if profile.get("title"):
                    personalized_body = personalized_body.replace(
                        "{title}", profile["title"]
                    )
                personalized_body = personalized_body.replace(
                    "{first_name}", profile["first_name"]
                )
                personalized_body = personalized_body.replace(
                    "{surname}", profile["surname"]
                )
                personalized_body = personalized_body.replace(
                    "{full_name}",
                    f"{profile.get('first_name', '')} {profile.get('surname', '')}".strip(),
                )
            elif greeting_type == "title_and_full_name":
                # Apply title and full name placeholders
                if profile.get("title"):
                    personalized_body = personalized_body.replace(
                        "{title}", profile["title"]
                    )
                personalized_body = personalized_body.replace(
                    "{full_name}",
                    f"{profile.get('first_name', '')} {profile.get('surname', '')}".strip(),
                )
            # "simple" greeting_type: no attendee-specific placeholders

            # Always interpolate event data and email
            personalized_body = personalized_body.replace("{email}", recipient)
            personalized_body = personalized_body.replace(
                "{event_title}", resolved_title
            )
            personalized_body = personalized_body.replace("{event_date}", resolved_date)
            personalized_body = personalized_body.replace(
                "{event_subtitle}", resolved_subtitle or ""
            )
            personalized_body = personalized_body.replace(
                "{event_location}", resolved_location or ""
            )

            # Send email
            msg = EmailMessage()
            msg["From"] = f"{from_name} <{from_email}>"
            msg["To"] = recipient
            msg["Subject"] = subject
            msg.set_content(personalized_body)
            msg.add_attachment(
                pdf_bytes,
                maintype="application",
                subtype="pdf",
                filename="certificate.pdf",
            )

            try:
                backend = os.environ.get("SMTP_BACKEND")
                logger = logging.getLogger(__name__)
                if backend == "console":
                    print(
                        f"TO: {recipient}\nSUBJECT: {subject}\n{personalized_body}\n[PDF {len(pdf_bytes)} bytes]\n"
                    )
                    logger.info("Sent console email to %s", recipient)
                else:
                    use_ssl = smtp_port == 465
                    if use_ssl:
                        server = smtplib.SMTP_SSL(smtp_host, smtp_port)
                    else:
                        server = smtplib.SMTP(smtp_host, smtp_port)
                        server.starttls()
                    try:
                        if smtp_username and smtp_password:
                            server.login(smtp_username, smtp_password)
                        server.send_message(msg)
                    finally:
                        server.quit()
                sent_emails.append(recipient)
            except Exception as exc:
                failed_emails.append({"email": recipient, "error": str(exc)})

        return {
            "status": "sent" if not failed_emails else "partial",
            "count": len(sent_emails),
            "total": len(email_jobs),
            "failures": failed_emails,
            "conference_title": resolved_title,
            "conference_date": resolved_date,
            "subtitle": resolved_subtitle,
            "location": resolved_location,
        }

    return {
        "status": "ok",
        "count": len(result.get("generated", [])),
        "conference_title": resolved_title,
        "conference_date": resolved_date,
        "subtitle": resolved_subtitle,
        "location": resolved_location,
    }
