import io
import csv
import base64
import zipfile
import importlib
import inspect
import logging
import sys
import smtplib
import tempfile
import os
from email.message import EmailMessage
from typing import List, Dict, Tuple, Optional

from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
import time
from pathlib import Path
from datetime import datetime

# (FastAPI app is created below with docs configured.)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.requests import Request
from fastapi.middleware.cors import CORSMiddleware


# Security: simple headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Prevent MIME sniffing
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        # Prevent clickjacking
        response.headers.setdefault("X-Frame-Options", "DENY")
        # Minimal referrer policy
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
)


def _find_generator():
    """Try to import the local `certify` package functions first.
    Falls back to attempting the previously used discovery on `certify_attendance`.
    """
    # Prefer published `certify_attendance` package (PyPI) when available
    try:
        module = importlib.import_module("certify_attendance")
        # try to find obvious single-file generators
        candidates = [
            "generate_certificates",
            "generate_pdfs",
            "render_certificates",
            "generate",
            "create_certificates",
        ]
        for name in candidates:
            if hasattr(module, name) and callable(getattr(module, name)):
                single = getattr(module, name)
                # try to import batch generator name if present on the package
                batch = getattr(module, "generate_batch", None)
                return {"single": single, "batch": batch}

        # search for any callable with pdf in the name
        for name, obj in vars(module).items():
            if callable(obj) and "pdf" in name.lower():
                batch = getattr(module, "generate_batch", None)
                return {"single": obj, "batch": batch}

        # look for a class with a generate-like method
        for name, obj in vars(module).items():
            if inspect.isclass(obj):
                for m in ("generate", "create", "render"):
                    if hasattr(obj, m):
                        instance = obj()
                        batch = getattr(module, "generate_batch", None)
                        return {"single": getattr(instance, m), "batch": batch}
    except Exception:
        # ignore and fallback to local package
        pass

    # Fallback to local `certify` package (workspace)
    try:
        from certify.main import create_certificate

        try:
            from certify.batch_generate import generate_batch
        except Exception:
            generate_batch = None

        return {"single": create_certificate, "batch": generate_batch}
    except Exception:
        raise RuntimeError(
            "Could not import 'certify_attendance' nor local 'certify' package"
        )


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


def _call_generator(
    generator_obj,
    attendees: List[Dict],
    title: str,
    date: str,
    logo_bytes: Optional[bytes] = None,
):
    """Support the `create_certificate` signature from the `certify` project.
    For single attendees, generate temporary PDF files and return in-memory bytes mapped to email.
    For batch generation, if `generate_batch` is available, use it to produce files and email jobs.
    """
    out: List[Tuple[str, bytes]] = []
    single_fn = (
        generator_obj.get("single")
        if isinstance(generator_obj, dict)
        else generator_obj
    )

    # If single create_certificate is available, call it per attendee writing to a temp file
    if single_fn:
        for a in attendees:
            # Build attendee name and output path
            attendee_name = (
                a.get("first_name")
                and a.get("surname")
                and f"{a.get('first_name')} {a.get('surname')}"
                or a.get("name")
                or a.get("attendee_name")
            )
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pdf")
            os.close(tmp_fd)
            # create_certificate signature expects attendee_name, course_title, location, date, output_path, organiser, organiser_logo, host_hospital, host_trust, host_name
            organiser_logo_path = None
            if logo_bytes:
                # write logo to temp file
                logo_fd, logo_path = tempfile.mkstemp(suffix=".png")
                with os.fdopen(logo_fd, "wb") as lf:
                    lf.write(logo_bytes)
                organiser_logo_path = logo_path

            try:
                # fill required fields with best-effort defaults
                course_title = title
                location = a.get("location", "")
                create_kwargs = {
                    "attendee_name": attendee_name,
                    "course_title": course_title,
                    "location": location or "",
                    "date": date,
                    "output_path": tmp_path,
                }
                # If the function accepts organiser_logo param, pass the path
                try:
                    # call with kwargs
                    single_fn(
                        **create_kwargs,
                        organiser_logo=organiser_logo_path or "logo.png",
                    )
                except TypeError:
                    # try positional fallback
                    single_fn(
                        attendee_name, course_title, location or "", date, tmp_path
                    )

                with open(tmp_path, "rb") as pf:
                    pdf_bytes = pf.read()
                out.append(
                    (
                        a.get("email", a.get("recipient", "unknown@example.com")),
                        pdf_bytes,
                    )
                )
            finally:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
                if logo_bytes and organiser_logo_path:
                    try:
                        os.remove(organiser_logo_path)
                    except Exception:
                        pass
        return out

    raise RuntimeError("No supported generator function found")


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
    logo_bytes = await logo.read() if logo else b""
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
    # Try to use the library's batch generator (in-memory) when available
    logo_bytes = await logo.read() if logo else b""
    batch_fn = None
    if isinstance(_GENERATOR, dict):
        batch_fn = _GENERATOR.get("batch")

    # write CSV to a temp file for the batch generator
    tmp_csv = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
    try:
        tmp_csv.write(csv_bytes)
        tmp_csv.close()
        tmp_csv_path = Path(tmp_csv.name)

        # prepare defaults for generate_batch
        organiser_logo_path = None
        if logo_bytes:
            lf = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
            lf.write(logo_bytes)
            lf.close()
            organiser_logo_path = str(lf.name)

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

        if batch_fn:
            # best-effort event_year
            event_year = str(datetime.now().year)
            try:
                res = batch_fn(
                    input_path=tmp_csv_path,
                    event_name=conference_title,
                    event_year=event_year,
                    defaults=defaults,
                    output_dir=None,
                    make_zip=True,
                    in_memory=True,
                )
            except TypeError:
                # older signatures - call with positional defaults
                res = batch_fn(
                    tmp_csv_path,
                    conference_title,
                    event_year,
                    defaults,
                    None,
                    True,
                    True,
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
                    with zipfile.ZipFile(
                        buf, "w", compression=zipfile.ZIP_DEFLATED
                    ) as zf:
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
                headers={
                    "Content-Disposition": "attachment; filename=certificates.zip"
                },
            )

        # Fallback path: use per-attendee generator as before
        attendees = _parse_csv(csv_bytes)
        pdf_items = _call_generator(
            _GENERATOR, attendees, conference_title, conference_date, logo_bytes or None
        )
        if review:
            zip_bytes = _create_zip(pdf_items)
            return StreamingResponse(
                io.BytesIO(zip_bytes),
                media_type="application/zip",
                headers={
                    "Content-Disposition": "attachment; filename=certificates.zip"
                },
            )
        if send:
            # Prefer environment values if form fields are omitted
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
        zip_bytes = _create_zip(pdf_items)
        return StreamingResponse(
            io.BytesIO(zip_bytes),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=certificates.zip"},
        )
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
