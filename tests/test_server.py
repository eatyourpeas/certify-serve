import sys
from pathlib import Path
import io
import zipfile

# Ensure the server package on src/ is importable when running tests from repo root
HERE = Path(__file__).resolve().parents[1]
SRC = HERE / "src"
sys.path.insert(0, str(SRC))

from fastapi.testclient import TestClient
import certify_server.main as mod
from certify_server.main import app


def fake_single(*args, **kwargs):
    # determine output path (kw or positional)
    output_path = kwargs.get("output_path")
    if not output_path:
        if len(args) >= 5:
            output_path = args[4]
        else:
            raise TypeError("missing output_path")
    with open(output_path, "wb") as fh:
        fh.write(b"%PDF-1.4\n%fake\n%%EOF")
    return output_path


def fake_batch(*args, **kwargs):
    # Accept both positional and kw invocation; return generated entries, zip bytes and email jobs
    pdf_bytes = b"%PDF-1.4\n%fakebatch\n%%EOF"
    generated = [{"name": "Test User", "filename": "test.pdf", "pdf_bytes": pdf_bytes}]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.pdf", pdf_bytes)
    return {
        "generated": generated,
        "zip": buf.getvalue(),
        "email_jobs": [
            {
                "recipient": "user@example.com",
                "pdf_bytes": pdf_bytes,
                "filename": "test.pdf",
            }
        ],
    }


def test_generate_single_review_and_zip():
    mod._GENERATOR = {"single": fake_single}
    client = TestClient(app)
    files = {"logo": ("logo.png", b"fakepng", "image/png")}
    data = {
        "first_name": "Jane",
        "surname": "Doe",
        "email": "jane@example.com",
        "conference_title": "Test Event",
        "conference_date": "2026-02-27",
        "review": "true",
    }
    r = client.post("/generate", data=data, files=files)
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("application/zip")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    namelist = z.namelist()
    assert any(n.endswith(".pdf") for n in namelist)


def test_generate_single_send_uses_send_emails():
    mod._GENERATOR = {"single": fake_single}
    captured = {}

    def fake_send(
        smtp_host,
        smtp_port,
        username,
        password,
        from_name,
        from_email,
        subject,
        body,
        pdf_items,
    ):
        captured["called"] = True
        captured["pdf_items"] = pdf_items

    orig_send = mod._send_emails
    mod._send_emails = fake_send
    try:
        client = TestClient(app)
        data = {
            "first_name": "John",
            "surname": "Smith",
            "email": "john@example.com",
            "conference_title": "Test Event",
            "conference_date": "2026-02-27",
            "send": "true",
            "review": "false",
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
        }
        r = client.post("/generate", data=data)
        assert r.status_code == 200
        assert captured.get("called") is True
        assert isinstance(captured.get("pdf_items"), list)
        assert len(captured["pdf_items"]) == 1
    finally:
        mod._send_emails = orig_send


def test_generate_csv_batch_review_and_send():
    mod._GENERATOR = {"batch": fake_batch}
    client = TestClient(app)
    csv_content = "name,attendee_email\nTest User,user@example.com\n"
    files = {"csv_file": ("attendees.csv", csv_content, "text/csv")}
    data = {
        "conference_title": "Batch Event",
        "conference_date": "2026-02-27",
        "review": "true",
    }
    r = client.post("/generate/csv", data=data, files=files)
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("application/zip")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert "test.pdf" in z.namelist()


def test_generate_csv_invalid_missing_columns():
    # Ensure batch is not used so the server falls back to CSV parser which validates headers
    mod._GENERATOR = {"single": fake_single}
    client = TestClient(app)
    # Missing email column
    csv_content = "Attendee first name,Attendee Surname\nAlice,Wonderland\n"
    files = {"csv_file": ("bad.csv", csv_content, "text/csv")}
    data = {"conference_title": "Bad Event", "conference_date": "2026-02-27"}
    r = client.post("/generate/csv", data=data, files=files)
    assert r.status_code == 422


def test_send_emails_function_monkeypatch_smtp():
    # Replace smtplib classes used by the module with a dummy implementation
    class DummyServer:
        def __init__(self, host, port):
            self.host = host
            self.port = port
            self.sent = []

        def starttls(self):
            pass

        def login(self, u, p):
            self.login = (u, p)

        def send_message(self, msg):
            self.sent.append(msg)

        def quit(self):
            self.closed = True

    orig_smtp = mod.smtplib.SMTP
    orig_ssl = mod.smtplib.SMTP_SSL
    try:
        mod.smtplib.SMTP = DummyServer
        mod.smtplib.SMTP_SSL = DummyServer
        # call with non-SSL port
        pdf = b"%PDF-1.4\n%pdf\n%%EOF"
        mod._send_emails(
            "smtp.example.com",
            587,
            "user",
            "pass",
            "Me",
            "me@example.com",
            "Subj",
            "Body",
            [("to@example.com", pdf)],
        )
        # call with SSL port
        mod._send_emails(
            "smtp.example.com",
            465,
            None,
            None,
            "Me",
            "me@example.com",
            "Subj",
            "Body",
            [("to2@example.com", pdf)],
        )
    finally:
        mod.smtplib.SMTP = orig_smtp
        mod.smtplib.SMTP_SSL = orig_ssl


def test_send_emails_console_backend(capsys, caplog):
    import os
    from io import StringIO
    from contextlib import redirect_stdout

    orig_backend = os.environ.get("SMTP_BACKEND")
    os.environ["SMTP_BACKEND"] = "console"
    try:
        pdf = b"%PDF-1.4\n%pdf\n%%EOF"
        caplog.set_level("INFO")
        buf = StringIO()
        with redirect_stdout(buf):
            res = mod._send_emails(
                "ignored",
                0,
                None,
                None,
                "Me",
                "me@example.com",
                "Subj",
                "Body",
                [("to@example.com", pdf)],
            )
        out = buf.getvalue()
        assert res == 1
        # also ensure log record created
        assert any("to@example.com" in r.getMessage() for r in caplog.records)
    finally:
        if orig_backend is None:
            del os.environ["SMTP_BACKEND"]
        else:
            os.environ["SMTP_BACKEND"] = orig_backend
