import io
import csv
import zipfile
import logging
import sys
import smtplib
import tempfile
import os
from email.message import EmailMessage
from typing import List, Dict, Tuple, Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Query
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import time
from pathlib import Path
from datetime import datetime

# (FastAPI app is created below with docs configured.)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.requests import Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

from certify import (
    create_certificate,
    generate_batch,
)  # the installed package we call to generate certificates


# Security: simple headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Prevent MIME sniffing
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        # Prevent clickjacking
        response.headers.setdefault("X-Frame-Options", "DENY")

        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # Add HSTS when HTTPS enforcement is enabled
        try:
            enforce = os.getenv("ENFORCE_HTTPS", "false").lower() in (
                "1",
                "true",
                "yes",
            )
            if enforce:
                hsts_age = int(os.getenv("HSTS_MAX_AGE", "31536000"))
                response.headers.setdefault(
                    "Strict-Transport-Security",
                    f"max-age={hsts_age}; includeSubDomains; preload",
                )
        except Exception:
            pass
        return response


# Body size limit middleware
class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_body: int = 10_485_760):
        super().__init__(app)
        self.max_body = int(max_body)

    async def dispatch(self, request: Request, call_next):
        # Fast path: use Content-Length header when present
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_body:
                    return JSONResponse(
                        {"detail": "Request body too large"}, status_code=413
                    )
            except Exception:
                pass
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter per client IP.

    Not suitable for multi-process or distributed deployments —
    it's a lightweight development-friendly limiter controlled via env vars:
    `RATE_LIMIT` (requests) and `RATE_PERIOD` (seconds).
    """

    def __init__(self, app, max_requests: int = 60, period: int = 60):
        super().__init__(app)
        self.max_requests = int(max_requests)
        self.period = int(period)
        # { ip: {"count": int, "start": float} }
        self.clients: Dict[str, Dict] = {}

    async def dispatch(self, request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        now = time.time()
        entry = self.clients.get(client)
        if entry is None or now - entry.get("start", 0) > self.period:
            # reset window
            self.clients[client] = {"count": 1, "start": now}
        else:
            entry["count"] += 1
            if entry["count"] > self.max_requests:
                retry_after = int(self.period - (now - entry["start"]))
                return JSONResponse(
                    {"detail": "Rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                )
        response = await call_next(request)
        return response


app = FastAPI(
    title="Certify Attendance Server",
    docs_url="/swagger",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    swagger_ui_parameters={"favicon_href": "/site/icons/favicon.svg"},
)

# If a `site` directory exists (e.g. during local dev or when bundled into the image),
# expose it at `/site` so the Swagger UI can load the custom favicon and other assets.
site_dir = Path(__file__).resolve().parents[2] / "site"
if site_dir.exists():
    app.mount("/site", StaticFiles(directory=str(site_dir)), name="site")
else:
    logging.getLogger(__name__).debug(
        "site directory not found; static assets not mounted: %s", site_dir
    )


# Serve a root favicon so browsers reliably show the tab icon.
@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    svg_path = site_dir / "icons" / "favicon.svg"
    if svg_path.exists():
        return FileResponse(svg_path, media_type="image/svg+xml")
    raise HTTPException(status_code=404, detail="favicon not found")


# Proxy common PNG favicon requests to the SVG so browsers and Swagger UI resolve an icon
@app.get("/favicon.png", include_in_schema=False)
@app.get("/favicon-32x32.png", include_in_schema=False)
@app.get("/favicon-16x16.png", include_in_schema=False)
def favicon_png():
    svg_path = site_dir / "icons" / "favicon.svg"
    if svg_path.exists():
        return FileResponse(svg_path, media_type="image/svg+xml")
    raise HTTPException(status_code=404, detail="favicon not found")


# Attach rate limiter using env-configured values (defaults safe for development)
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "60"))
RATE_PERIOD = int(os.getenv("RATE_PERIOD", "60"))
app.add_middleware(RateLimitMiddleware, max_requests=RATE_LIMIT, period=RATE_PERIOD)


# Attach CORS, security headers and body size limit
allowed = os.getenv("ALLOWED_ORIGINS", "*")
origins = [o.strip() for o in allowed.split(",")] if allowed else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
MAX_BODY = int(os.getenv("MAX_BODY_SIZE", str(10 * 1024 * 1024)))
app.add_middleware(BodySizeLimitMiddleware, max_body=MAX_BODY)


# Enforce HTTPS middleware: redirects to https or rejects non-https when enabled
class EnforceHTTPSMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.enforce = os.getenv("ENFORCE_HTTPS", "false").lower() in (
            "1",
            "true",
            "yes",
        )

    async def dispatch(self, request: Request, call_next):
        if not self.enforce:
            return await call_next(request)

        # Determine scheme: respect X-Forwarded-Proto for proxies
        proto = request.headers.get("x-forwarded-proto") or request.url.scheme
        if proto != "https":
            # Build HTTPS URL and redirect
            url = request.url.replace(scheme="https")
            from starlette.responses import RedirectResponse

            return RedirectResponse(url, status_code=308)

        return await call_next(request)


# Insert EnforceHTTPSMiddleware near the top of the stack if enabled
if os.getenv("ENFORCE_HTTPS", "false").lower() in ("1", "true", "yes"):
    app.add_middleware(EnforceHTTPSMiddleware)


@app.get("/health")
def health():
    """Health check endpoint returning OK and timestamp."""
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}


class SendResponse(BaseModel):
    status: str
    count: int


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


@app.post(
    "/generate/eventbrite",
    summary="Generate certificates from Eventbrite attendees",
    description=(
        "Fetch attendees for an Eventbrite event and generate certificates. "
        "Provide `event_id` and optionally override `EVENTBRITE_TOKEN` via form. "
        "Set `review=true` to return a ZIP of the generated PDFs or `send=true` to email them."
    ),
)
async def generate_eventbrite(
    event_id: str = Form(
        ..., description="Eventbrite event id", examples=["1234567890"]
    ),
    eventbrite_token: Optional[str] = Form(
        None,
        description="Optional Eventbrite token (falls back to EVENTBRITE_TOKEN env)",
    ),
    status: str = Form(
        "",
        description=(
            "Optional attendee status filter (e.g. attending, cancelled). "
            "When empty (default) no status filter is sent so completed/past events are included."
        ),
        examples=["", "attending", "cancelled"],
    ),
    logo: Optional[UploadFile] = File(
        None, description="Optional organiser logo to include on certificates"
    ),
    review: bool = Form(
        True, description="If true return ZIP for review", examples=[True, False]
    ),
    send: bool = Form(
        False,
        description="If true send generated PDFs by email",
        examples=[True, False],
    ),
    smtp_host: Optional[str] = Form(
        None, description="Optional SMTP host (falls back to SMTP_HOST env)"
    ),
    smtp_port: Optional[int] = Form(
        None,
        description="Optional SMTP port (falls back to SMTP_PORT env)",
        examples=[587],
    ),
    smtp_username: Optional[str] = Form(
        None, description="Optional SMTP username (falls back to SMTP_USERNAME env)"
    ),
    smtp_password: Optional[str] = Form(
        None, description="Optional SMTP password (falls back to SMTP_PASSWORD env)"
    ),
    from_name: str = Form(
        "Conference Team", description="From name for outgoing emails"
    ),
    from_email: str = Form(
        "noreply@example.com", description="From email for outgoing emails"
    ),
    subject: str = Form("Your attendance certificate"),
    body: str = Form("Please find your attendance certificate attached."),
):
    """Fetch attendees from Eventbrite and generate certificates for them.

    This endpoint requires `EVENTBRITE_TOKEN` in the environment or a token passed
    via the `eventbrite_token` form field. The token is sent as `Authorization: Bearer <token>`.
    """
    token = eventbrite_token or os.getenv("EVENTBRITE_TOKEN")
    if not token:
        raise HTTPException(
            status_code=422,
            detail="Eventbrite token required (EVENTBRITE_TOKEN or form)",
        )
    token = str(token).strip().strip('"').strip("'")
    if token.lower().startswith("bearer "):
        token = token.split(None, 1)[1]

    headers = {"Authorization": f"Bearer {token}", "Host": "www.eventbriteapi.com"}
    attendees_url = f"https://www.eventbriteapi.com/v3/events/{event_id}/attendees/"
    event_url = f"https://www.eventbriteapi.com/v3/events/{event_id}/"

    try:
        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            # event metadata
            evr = await client.get(event_url)
            if evr.status_code == 401:
                raise HTTPException(
                    status_code=401, detail=f"Eventbrite unauthorized: {evr.text}"
                )
            evr.raise_for_status()
            ev = evr.json()
            course_title = (ev.get("name") or {}).get("text") or ""
            course_date = (
                (ev.get("start") or {}).get("local")
                or (ev.get("start") or {}).get("utc")
                or ""
            )

            # fetch all attendees (paginated)
            attendees_raw = []
            continuation = None
            while True:
                params = {}
                if status:
                    params["status"] = status
                if continuation:
                    params["continuation"] = continuation
                resp = await client.get(attendees_url, params=params)
                if resp.status_code == 401:
                    raise HTTPException(
                        status_code=401, detail=f"Eventbrite unauthorized: {resp.text}"
                    )
                if resp.status_code == 429:
                    ra = resp.headers.get("Retry-After")
                    raise HTTPException(
                        status_code=503,
                        detail=f"Eventbrite rate limited; retry after {ra}",
                    )
                resp.raise_for_status()
                data = resp.json()
                attendees_raw.extend(data.get("attendees", []))
                pagination = data.get("pagination", {})
                if not pagination.get("has_more_items"):
                    break
                continuation = pagination.get("continuation")
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Eventbrite fetch failed: {exc}")

    if not attendees_raw:
        raise HTTPException(status_code=404, detail="No attendees found for event")

    # prepare organiser logo file path if provided
    organiser_logo_path = None
    if logo:
        logo_bytes = await logo.read()
        lf = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        lf.write(logo_bytes)
        lf.close()
        organiser_logo_path = str(lf.name)

    # build temp CSV with header matching generate_batch expectations
    tmp_csv = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
    try:
        with open(tmp_csv.name, "w", encoding="utf-8") as fh:
            # header: attendee_name plus supported override columns
            headers_cols = [
                "attendee_name",
                "output_filename",
                "host_name",
                "organiser",
                "organiser_logo",
                "course_title",
                "location",
                "date",
                "host_hospital",
                "host_trust",
            ]
            fh.write(",".join(headers_cols) + "\n")
            for a in attendees_raw:
                profile = a.get("profile", {})
                name = profile.get("name") or " ".join(
                    filter(None, [profile.get("first_name"), profile.get("last_name")])
                )
                # sanity: skip if no email (we don't want to generate for anonymous entries)
                email = profile.get("email")
                if not email:
                    logging.getLogger(__name__).warning(
                        "Skipping attendee without email (id=%s)", a.get("id")
                    )
                    continue
                # output filename safe: use email-based name
                output_filename = (
                    email.replace("@", "_at_").replace(".", "_")
                ) + ".pdf"
                row = [
                    _csv_escape(name),
                    _csv_escape(output_filename),
                    _csv_escape(""),
                    _csv_escape(from_name),
                    _csv_escape(organiser_logo_path or ""),
                    _csv_escape(course_title),
                    _csv_escape(""),
                    _csv_escape(course_date),
                    _csv_escape(""),
                    _csv_escape(""),
                ]
                fh.write(",".join(row) + "\n")

        tmp_csv_path = Path(tmp_csv.name)

        # call the installed package's batch generator
        try:
            batch_fn = generate_batch
            if not batch_fn:
                raise RuntimeError("generate_batch not found on certify package")

            res = batch_fn(
                input_path=tmp_csv_path,
                event_name=course_title,
                event_year=str(datetime.now().year),
                defaults={
                    "organiser": from_name,
                    "organiser_logo": organiser_logo_path,
                    "course_title": course_title,
                    "location": "",
                    "date": course_date,
                    "host_hospital": "",
                    "host_trust": "",
                    "host_name": "",
                },
                output_dir=None,
                make_zip=True,
                in_memory=True,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=500, detail=f"Batch generation failed: {exc}"
            )

        # Handle review request: return zip file
        if review:
            zip_bytes = res.get("zip")
            if zip_bytes:
                return StreamingResponse(
                    io.BytesIO(zip_bytes),
                    media_type="application/zip",
                    headers={
                        "Content-Disposition": "attachment; filename=certificates.zip"
                    },
                )
            # fallback: build zip from generated entries
            generated = res.get("generated") or []
            if generated:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for g in generated:
                        name = g.get("filename") or (g.get("name") or "certificate.pdf")
                        zf.writestr(name, g.get("pdf_bytes") or b"")
                buf.seek(0)
                return StreamingResponse(
                    buf,
                    media_type="application/zip",
                    headers={
                        "Content-Disposition": "attachment; filename=certificates.zip"
                    },
                )

        # Handle send request: email certificates
        if send:
            # Prefer environment values if form fields omitted
            smtp_host = smtp_host or os.getenv("SMTP_HOST")
            smtp_port = smtp_port or os.getenv("SMTP_PORT")
            smtp_username = smtp_username or os.getenv("SMTP_USERNAME")
            smtp_password = smtp_password or os.getenv("SMTP_PASSWORD")
            from_name = from_name or os.getenv("FROM_NAME", from_name)
            from_email = from_email or os.getenv("FROM_EMAIL", from_email)

            if not smtp_host or not smtp_port:
                raise HTTPException(
                    status_code=422,
                    detail="SMTP host and port required to send emails",
                )
            try:
                smtp_port_val = int(smtp_port)
            except Exception:
                raise HTTPException(status_code=422, detail="Invalid SMTP port")

            email_jobs = res.get("email_jobs") or []
            pdf_items: List[Tuple[str, bytes]] = []
            for job in email_jobs:
                recipient = job.get("recipient")
                pdf = job.get("pdf_bytes") or None
                if not pdf and job.get("filepath"):
                    try:
                        with open(job.get("filepath"), "rb") as fh:
                            pdf = fh.read()
                    except Exception:
                        pdf = None
                if recipient and pdf:
                    pdf_items.append((recipient, pdf))

            _send_emails(
                smtp_host,
                smtp_port_val,
                smtp_username,
                smtp_password,
                from_name,
                from_email,
                subject,
                body,
                pdf_items,
            )
            return {"status": "sent", "count": len(pdf_items)}

        # default: return zip file
        zip_bytes = res.get("zip")
        if zip_bytes:
            return StreamingResponse(
                io.BytesIO(zip_bytes),
                media_type="application/zip",
                headers={
                    "Content-Disposition": "attachment; filename=certificates.zip"
                },
            )
        generated = res.get("generated") or []
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for g in generated:
                name = g.get("filename") or (g.get("name") or "certificate.pdf")
                zf.writestr(name, g.get("pdf_bytes") or b"")
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=certificates.zip"},
        )
    finally:
        try:
            os.unlink(tmp_csv.name)
        except Exception:
            pass
        if organiser_logo_path:
            try:
                os.unlink(organiser_logo_path)
            except Exception:
                pass


def _create_zip(pdf_items: List[Tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for email, pdf in pdf_items:
            # sanitize filename
            name = email.replace("@", "_at_").replace(".", "_")
            zf.writestr(f"{name}.pdf", pdf)
    buf.seek(0)
    return buf.read()


def _csv_escape(val: Optional[str]) -> str:
    """Escape a CSV cell for minimal CSV writing.

    - Converts None to empty string
    - Wraps value in double quotes if it contains comma, quote, or newline
    - Doubles internal quotes per CSV rules
    """
    if val is None:
        return ""
    s = str(val)
    if any(ch in s for ch in [",", '"', "\n", "\r"]):
        s = '"' + s.replace('"', '""') + '"'
    return s


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
    # Support a console backend for development: set SMTP_BACKEND=console
    backend = os.getenv("SMTP_BACKEND", "smtp").lower()
    if backend == "console":
        logger = logging.getLogger(__name__)
        logger.info("[SMTP-Console] Sending emails (simulated):")
        sys.stdout.write("[SMTP-Console] Sending emails (simulated):\n")
        for to_email, pdf in pdf_items:
            line = f"- To: {to_email} | Size: {len(pdf)} bytes | From: {from_name} <{from_email}>\n"
            logger.info(line.strip())
            sys.stdout.write(line)
        sys.stdout.flush()
        return len(pdf_items)

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


@app.post(
    "/generate",
    summary="Generate single certificate",
    description=(
        "Generate a single attendance certificate for one attendee. "
        "By default the endpoint returns a ZIP file for review. Set `send=true` "
        "to email the certificate to the attendee (requires SMTP settings). "
        "Example curl: `curl -F 'first_name=Jane' -F 'surname=Doe' "
        "-F 'email=jane@example.com' -F 'conference_title=Fireside' "
        "-F 'conference_date=2026-02-27' http://localhost:8000/generate -o certs.zip`"
    ),
    responses={
        200: {
            "description": "ZIP download or JSON send confirmation",
            "content": {
                "application/json": {"example": {"status": "sent", "count": 1}},
                "application/zip": {"example": "(binary ZIP file)"},
            },
        },
        422: {
            "description": "Validation error",
            "content": {
                "application/json": {
                    "example": {"detail": "SMTP host and port required to send emails"}
                }
            },
        },
        500: {
            "description": "Server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "certify_attendance generator not available on startup"
                    }
                }
            },
        },
    },
)
async def generate_single(
    first_name: str = Form(..., description="Attendee first name", examples=["Jane"]),
    surname: str = Form(..., description="Attendee surname", examples=["Doe"]),
    email: str = Form(
        ..., description="Attendee email address", examples=["jane@example.com"]
    ),
    conference_title: str = Form(
        ..., description="Event / conference title", examples=["Fireside Conference"]
    ),
    conference_date: str = Form(
        ...,
        description="Date for the certificate (ISO YYYY-MM-DD)",
        examples=["2026-02-27"],
    ),
    logo: Optional[UploadFile] = File(
        None,
        description="Optional organiser logo (PNG/JPEG) to embed on the certificate",
    ),
    review: bool = Form(
        True,
        description="If true return a ZIP of generated PDFs for review",
        examples=[True],
    ),
    send: bool = Form(
        False,
        description="If true send the generated PDF by email to the attendee",
        examples=[False],
    ),
    smtp_host: Optional[str] = Form(
        None,
        description="Optional SMTP host (falls back to SMTP_HOST env)",
        examples=["smtp.example.com"],
    ),
    smtp_port: Optional[int] = Form(
        None,
        description="Optional SMTP port (falls back to SMTP_PORT env)",
        examples=[587],
    ),
    smtp_username: Optional[str] = Form(
        None,
        description="Optional SMTP username (falls back to SMTP_USERNAME env)",
        examples=["user@example.com"],
    ),
    smtp_password: Optional[str] = Form(
        None,
        description="Optional SMTP password (falls back to SMTP_PASSWORD env)",
        examples=["password"],
    ),
    from_name: str = Form(
        "Conference Team",
        description="From name for outgoing emails",
        examples=["Conference Team"],
    ),
    from_email: str = Form(
        "noreply@example.com",
        description="From email address for outgoing emails",
        examples=["noreply@example.com"],
    ),
    subject: str = Form(
        "Your attendance certificate",
        description="Email subject when sending",
        examples=["Your attendance certificate"],
    ),
    body: str = Form(
        "Please find your attendance certificate attached.",
        description="Email body when sending",
        examples=["Please find your attendance certificate attached."],
    ),
):
    logo_bytes = await logo.read() if logo else b""
    # Prepare organiser logo file path if provided
    organiser_logo_path = None
    if logo_bytes:
        lf = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        lf.write(logo_bytes)
        lf.close()
        organiser_logo_path = str(lf.name)

    # Generate single certificate
    try:
        attendee_name = f"{first_name} {surname}"
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pdf")
        os.close(tmp_fd)

        create_certificate(
            attendee_name=attendee_name,
            course_title=conference_title,
            location="",
            date=conference_date,
            output_path=tmp_path,
            organiser_logo=organiser_logo_path or "logo.png",
        )

        with open(tmp_path, "rb") as pf:
            pdf_bytes = pf.read()
        pdf_items = [(email, pdf_bytes)]
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        if organiser_logo_path:
            try:
                os.remove(organiser_logo_path)
            except Exception:
                pass

    if review:
        # return a zip for the single item as stream
        zip_bytes = _create_zip(pdf_items)
        return StreamingResponse(
            io.BytesIO(zip_bytes),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=certificates.zip"},
        )
    if send:
        # Prefer environment values if form fields omitted
        smtp_host = smtp_host or os.getenv("SMTP_HOST")
        smtp_port = smtp_port or os.getenv("SMTP_PORT")
        smtp_username = smtp_username or os.getenv("SMTP_USERNAME")
        smtp_password = smtp_password or os.getenv("SMTP_PASSWORD")
        from_name = from_name or os.getenv("FROM_NAME", from_name)
        from_email = from_email or os.getenv("FROM_EMAIL", from_email)

        if not smtp_host or not smtp_port:
            raise HTTPException(
                status_code=422, detail="SMTP host and port required to send emails"
            )
        try:
            smtp_port_val = int(smtp_port)
        except Exception:
            raise HTTPException(status_code=422, detail="Invalid SMTP port")

        _send_emails(
            smtp_host,
            smtp_port_val,
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


@app.post(
    "/generate/csv",
    summary="Generate batch certificates from CSV",
    description=(
        "Upload a CSV with attendee rows to generate certificates in batch. "
        "CSV headers are case-insensitive and must include columns containing 'first', "
        "'surname' (or 'last') and 'email'. By default the endpoint returns a ZIP. "
        "Set `send=true` to email results using the provided SMTP settings or env vars."
    ),
    responses={
        200: {
            "description": "ZIP download or JSON send confirmation",
            "content": {
                "application/json": {"example": {"status": "sent", "count": 3}},
                "application/zip": {"example": "(binary ZIP file)"},
            },
        },
        422: {
            "description": "Validation error",
            "content": {
                "application/json": {
                    "example": {"detail": "CSV missing expected columns (found: [...])"}
                }
            },
        },
        500: {
            "description": "Server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "certify_attendance generator not available on startup"
                    }
                }
            },
        },
    },
)
async def generate_csv(
    csv_file: UploadFile = File(
        ...,
        description="CSV file with attendee rows. Required headers: first, surname/last, email.",
    ),
    conference_title: str = Form(
        ..., description="Event / conference title", examples=["Fireside Conference"]
    ),
    conference_date: str = Form(
        ...,
        description="Date for the certificates (ISO YYYY-MM-DD)",
        examples=["2026-02-27"],
    ),
    logo: Optional[UploadFile] = File(
        None, description="Optional organiser logo to include on certificates"
    ),
    review: bool = Form(
        True, description="If true return ZIP for review", examples=[True, False]
    ),
    send: bool = Form(
        False,
        description="If true send generated PDFs by email",
        examples=[True, False],
    ),
    smtp_host: Optional[str] = Form(
        None, description="Optional SMTP host (falls back to SMTP_HOST env)"
    ),
    smtp_port: Optional[int] = Form(
        None,
        description="Optional SMTP port (falls back to SMTP_PORT env)",
        examples=[587],
    ),
    smtp_username: Optional[str] = Form(
        None, description="Optional SMTP username (falls back to SMTP_USERNAME env)"
    ),
    smtp_password: Optional[str] = Form(
        None, description="Optional SMTP password (falls back to SMTP_PASSWORD env)"
    ),
    from_name: str = Form(
        "Conference Team",
        description="From name for outgoing emails",
        examples=["Conference Team"],
    ),
    from_email: str = Form(
        "noreply@example.com",
        description="From email for outgoing emails",
        examples=["noreply@example.com"],
    ),
    subject: str = Form(
        "Your attendance certificate", description="Email subject when sending"
    ),
    body: str = Form(
        "Please find your attendance certificate attached.",
        description="Email body when sending",
    ),
):
    csv_bytes = await csv_file.read()
    logo_bytes = await logo.read() if logo else b""
    # Prepare organiser logo file path if provided
    organiser_logo_path = None
    if logo_bytes:
        lf = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        lf.write(logo_bytes)
        lf.close()
        organiser_logo_path = str(lf.name)

    # write CSV to a temp file for the batch generator
    tmp_csv = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
    try:
        tmp_csv.write(csv_bytes)
        tmp_csv.close()
        tmp_csv_path = Path(tmp_csv.name)

        defaults = {
            "organiser": from_name,
            "organiser_logo": organiser_logo_path,
            "course_title": conference_title,
            "location": "",
            "date": conference_date,
            "host_hospital": "",
            "host_trust": "",
            "host_name": "",
        }

        # Use the batch generator from the certify package
        event_year = str(datetime.now().year)
        res = generate_batch(
            input_path=tmp_csv_path,
            event_name=conference_title,
            event_year=event_year,
            defaults=defaults,
            output_dir=None,
            make_zip=True,
            in_memory=True,
        )

        # If review requested, prefer an in-memory zip from the batch result
        if review:
            zip_bytes = res.get("zip")
            if zip_bytes:
                return StreamingResponse(
                    io.BytesIO(zip_bytes),
                    media_type="application/zip",
                    headers={
                        "Content-Disposition": "attachment; filename=certificates.zip"
                    },
                )
            # fallback: build zip from generated entries
            generated = res.get("generated") or []
            if generated:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for g in generated:
                        name = g.get("filename") or (g.get("name") or "certificate")
                        zf.writestr(name, g.get("pdf_bytes") or b"")
                buf.seek(0)
                return StreamingResponse(
                    buf,
                    media_type="application/zip",
                    headers={
                        "Content-Disposition": "attachment; filename=certificates.zip"
                    },
                )

        # If send requested, use email_jobs produced by the batch generator
        if send:
            # Prefer environment values if form fields omitted
            smtp_host = smtp_host or os.getenv("SMTP_HOST")
            smtp_port = smtp_port or os.getenv("SMTP_PORT")
            smtp_username = smtp_username or os.getenv("SMTP_USERNAME")
            smtp_password = smtp_password or os.getenv("SMTP_PASSWORD")
            from_name = from_name or os.getenv("FROM_NAME", from_name)
            from_email = from_email or os.getenv("FROM_EMAIL", from_email)

            if not smtp_host or not smtp_port:
                raise HTTPException(
                    status_code=422,
                    detail="SMTP host and port required to send emails",
                )
            try:
                smtp_port_val = int(smtp_port)
            except Exception:
                raise HTTPException(status_code=422, detail="Invalid SMTP port")
            email_jobs = res.get("email_jobs") or []
            pdf_items: List[Tuple[str, bytes]] = []
            for job in email_jobs:
                recipient = job.get("recipient")
                pdf = job.get("pdf_bytes") or None
                if not pdf and job.get("filepath"):
                    try:
                        with open(job.get("filepath"), "rb") as fh:
                            pdf = fh.read()
                    except Exception:
                        pdf = None
                if recipient and pdf:
                    pdf_items.append((recipient, pdf))
            _send_emails(
                smtp_host,
                smtp_port_val,
                smtp_username,
                smtp_password,
                from_name,
                from_email,
                subject,
                body,
                pdf_items,
            )
            return {"status": "sent", "count": len(pdf_items)}

        # default: return zip (if any) or rebuild from generated
        zip_bytes = res.get("zip")
        if zip_bytes:
            return StreamingResponse(
                io.BytesIO(zip_bytes),
                media_type="application/zip",
                headers={
                    "Content-Disposition": "attachment; filename=certificates.zip"
                },
            )
        generated = res.get("generated") or []
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for g in generated:
                name = g.get("filename") or (g.get("name") or "certificate")
                zf.writestr(name, g.get("pdf_bytes") or b"")
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=certificates.zip"},
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Batch generation failed: {exc}")
    finally:
        try:
            os.unlink(tmp_csv.name)
        except Exception:
            pass
        try:
            if organiser_logo_path:
                os.unlink(organiser_logo_path)
        except Exception:
            pass


@app.get(
    "/eventbrite/latest",
    summary="Get latest Eventbrite event for the authenticated user's first organization",
    description=(
        "Fetch the user's organizations via `/users/me/organizations/`, take the first organization, "
        "list that organization's events and return the latest event by start date. "
        "Requires `EVENTBRITE_TOKEN` in environment or `eventbrite_token` query parameter."
    ),
)
async def eventbrite_latest(
    eventbrite_token: Optional[str] = Query(
        None,
        description="Eventbrite token override (falls back to EVENTBRITE_TOKEN env)",
    ),
    org_id: Optional[str] = Query(
        None,
        description="Optional organization id to use instead of discovering via /users/me/organizations/",
    ),
    status: str = Query(
        "",
        description=(
            "Optional event status filter (e.g. live, draft, started, ended). "
            "When empty (default) no status filter is sent so past/completed events are included."
        ),
        examples=["", "live", "draft", "started", "ended"],
    ),
):
    token = eventbrite_token or os.getenv("EVENTBRITE_TOKEN")
    if not token:
        raise HTTPException(
            status_code=422,
            detail="Eventbrite token required (EVENTBRITE_TOKEN or eventbrite_token)",
        )
    token = str(token).strip().strip('"').strip("'")
    if token.lower().startswith("bearer "):
        token = token.split(None, 1)[1]

    headers = {"Authorization": f"Bearer {token}", "Host": "www.eventbriteapi.com"}

    async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
        # discover org if not provided
        if not org_id:
            try:
                resp = await client.get(
                    "https://www.eventbriteapi.com/v3/users/me/organizations/"
                )
                if resp.status_code == 429:
                    ra = resp.headers.get("Retry-After")
                    raise HTTPException(
                        status_code=503,
                        detail=f"Eventbrite rate limited; retry after {ra}",
                    )
                resp.raise_for_status()
                data = resp.json()
                orgs = data.get("organizations") or []
                if not orgs:
                    raise HTTPException(
                        status_code=404, detail="No organizations found for user"
                    )
                org_id = orgs[0].get("id")
            except httpx.HTTPError as exc:
                raise HTTPException(
                    status_code=502,
                    detail=f"Eventbrite organizations fetch failed: {exc}",
                )

        # fetch events for organization (paginated)
        events: List[Dict] = []
        url = f"https://www.eventbriteapi.com/v3/organizations/{org_id}/events/"
        continuation = None
        try:
            while True:
                params = {}
                if status:
                    params["status"] = status
                if continuation:
                    params["continuation"] = continuation
                resp = await client.get(url, params=params)
                if resp.status_code == 429:
                    ra = resp.headers.get("Retry-After")
                    raise HTTPException(
                        status_code=503,
                        detail=f"Eventbrite rate limited; retry after {ra}",
                    )
                resp.raise_for_status()
                data = resp.json()
                events.extend(data.get("events", []))
                pagination = data.get("pagination", {})
                if not pagination.get("has_more_items"):
                    break
                continuation = pagination.get("continuation")
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=502, detail=f"Eventbrite events fetch failed: {exc}"
            )

    if not events:
        raise HTTPException(status_code=404, detail="No events found for organization")

    # sort by start.utc (fallback to start.local) descending and return first
    def _start_key(ev: Dict) -> str:
        st = ev.get("start") or {}
        return st.get("utc") or st.get("local") or ""

    events_sorted = sorted(events, key=_start_key, reverse=True)
    latest = events_sorted[0]
    return latest
