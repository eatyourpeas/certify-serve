import sys
from pathlib import Path
import io
import zipfile

# Ensure server package importable
HERE = Path(__file__).resolve().parents[1]
SRC = HERE / "src"
sys.path.insert(0, str(SRC))

from fastapi.testclient import TestClient
import certify_server.main as mod
from certify_server.main import app
import httpx


def fake_batch(*args, **kwargs):
    pdf_bytes = b"%PDF-1.4\n%fakebatch\n%%EOF"
    generated = [{"name": "Test User", "filename": "test.pdf", "pdf_bytes": pdf_bytes}]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.pdf", pdf_bytes)
    return {
        "generated": generated,
        "zip": buf.getvalue(),
        "email_jobs": [{"recipient": "user@example.com", "pdf_bytes": pdf_bytes}],
    }


class DummyResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text
        self.headers = {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://www.eventbriteapi.com/v3/mock")
            response = httpx.Response(
                self.status_code,
                request=request,
                text=self.text or "",
            )
            raise httpx.HTTPStatusError(
                f"status={self.status_code}",
                request=request,
                response=response,
            )


class DummyAsyncClient:
    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, params=None, headers=None):
        # event metadata
        if url.endswith("/events/123/"):
            return DummyResponse(
                200,
                json_data={
                    "name": {"text": "Mock Event"},
                    "start": {"local": "2026-02-27T09:00:00"},
                },
            )
        # attendees list
        if url.endswith("/attendees/"):
            return DummyResponse(
                200,
                json_data={
                    "attendees": [
                        {
                            "profile": {
                                "first_name": "Alice",
                                "last_name": "A",
                                "email": "alice@example.com",
                            }
                        }
                    ],
                    "pagination": {"has_more_items": False},
                },
            )
        # fallback
        return DummyResponse(404, json_data={})


def test_generate_eventbrite_uses_batch_and_returns_zip(monkeypatch):
    # Patch httpx.AsyncClient used by the module
    monkeypatch.setattr(httpx, "AsyncClient", DummyAsyncClient)
    # Patch generate_batch to use our fake implementation
    monkeypatch.setattr(mod, "generate_batch", fake_batch)
    # ensure generator batch available
    client = TestClient(app)
    data = {"event_id": "123", "eventbrite_token": "tok", "review": "true"}
    r = client.post("/generate/eventbrite", data=data)
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("application/zip")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert "test.pdf" in z.namelist()


def test_preview_eventbrite_returns_metadata(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", DummyAsyncClient)
    client = TestClient(app)
    data = {"event_id": "123", "eventbrite_token": "tok"}
    r = client.post("/generate/eventbrite/preview", data=data)
    assert r.status_code == 200
    payload = r.json()
    assert payload["conference_title"] == "Mock Event"
    assert payload["conference_date"] == "2026-02-27T09:00:00"


def test_preview_eventbrite_get_returns_metadata(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", DummyAsyncClient)
    client = TestClient(app)
    r = client.get(
        "/generate/eventbrite/preview",
        params={"event_id": "123", "eventbrite_token": "tok"},
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload["conference_title"] == "Mock Event"


def test_preview_eventbrite_trailing_slash_post_returns_metadata(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", DummyAsyncClient)
    client = TestClient(app)
    data = {"event_id": "123", "eventbrite_token": "tok"}
    r = client.post("/generate/eventbrite/preview/", data=data)
    assert r.status_code == 200
    payload = r.json()
    assert payload["conference_title"] == "Mock Event"


def test_generate_eventbrite_retries_when_status_param_rejected(monkeypatch):
    class DummyAsyncClientStatus400(DummyAsyncClient):
        async def get(self, url, params=None, headers=None):
            if url.endswith("/events/123/"):
                return DummyResponse(
                    200,
                    json_data={
                        "name": {"text": "Mock Event"},
                        "start": {"local": "2026-02-27T09:00:00"},
                    },
                )
            if url.endswith("/attendees/"):
                if params and params.get("status"):
                    return DummyResponse(400, text="invalid status")
                return DummyResponse(
                    200,
                    json_data={
                        "attendees": [
                            {
                                "status": "attending",
                                "checked_in": True,
                                "profile": {
                                    "first_name": "Alice",
                                    "last_name": "A",
                                    "email": "alice@example.com",
                                },
                            }
                        ],
                        "pagination": {"has_more_items": False},
                    },
                )
            return DummyResponse(404, json_data={})

    monkeypatch.setattr(httpx, "AsyncClient", DummyAsyncClientStatus400)
    monkeypatch.setattr(mod, "generate_batch", fake_batch)
    client = TestClient(app)
    r = client.post(
        "/generate/eventbrite",
        data={
            "event_id": "123",
            "eventbrite_token": "tok",
            "review": "true",
            "status": "attended",
        },
    )
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("application/zip")


def test_generate_eventbrite_uses_metadata_location_when_form_location_empty(
    monkeypatch,
):
    captured = {}

    async def fake_metadata(event_id, token):
        return {
            "event_id": event_id,
            "conference_title": "Mock Event",
            "conference_date": "2026-02-27",
            "subtitle": "Mock Subtitle",
            "location": "Brighton Centre",
        }

    def fake_batch_capture(attendees, title, date, subtitle, location, logo_bytes=None):
        captured["location"] = location
        return fake_batch()

    monkeypatch.setattr(mod, "_fetch_eventbrite_event_metadata", fake_metadata)
    monkeypatch.setattr(httpx, "AsyncClient", DummyAsyncClient)
    monkeypatch.setattr(mod, "generate_batch", fake_batch_capture)

    client = TestClient(app)
    r = client.post(
        "/generate/eventbrite",
        data={
            "event_id": "123",
            "eventbrite_token": "tok",
            "review": "true",
            "location": "",
        },
    )

    assert r.status_code == 200
    assert captured["location"] == "Brighton Centre"


def test_generate_eventbrite_uses_form_location_override(monkeypatch):
    captured = {}

    async def fake_metadata(event_id, token):
        return {
            "event_id": event_id,
            "conference_title": "Mock Event",
            "conference_date": "2026-02-27",
            "subtitle": "Mock Subtitle",
            "location": "Brighton Centre",
        }

    def fake_batch_capture(attendees, title, date, subtitle, location, logo_bytes=None):
        captured["location"] = location
        return fake_batch()

    monkeypatch.setattr(mod, "_fetch_eventbrite_event_metadata", fake_metadata)
    monkeypatch.setattr(httpx, "AsyncClient", DummyAsyncClient)
    monkeypatch.setattr(mod, "generate_batch", fake_batch_capture)

    client = TestClient(app)
    r = client.post(
        "/generate/eventbrite",
        data={
            "event_id": "123",
            "eventbrite_token": "tok",
            "review": "true",
            "location": "Custom Venue",
        },
    )

    assert r.status_code == 200
    assert captured["location"] == "Custom Venue"


def test_list_eventbrite_attendees_returns_rows(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", DummyAsyncClient)
    client = TestClient(app)
    r = client.post(
        "/generate/eventbrite/attendees",
        data={"event_id": "123", "eventbrite_token": "tok"},
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload["count"] == 1
    assert payload["attendees"][0]["email"] == "alice@example.com"


def test_generate_eventbrite_selected_emails_filters(monkeypatch):
    captured = {}

    def fake_batch_capture(attendees, title, date, subtitle, location, logo_bytes=None):
        captured["attendees"] = attendees
        return fake_batch()

    monkeypatch.setattr(httpx, "AsyncClient", DummyAsyncClient)
    monkeypatch.setattr(mod, "generate_batch", fake_batch_capture)

    client = TestClient(app)
    r = client.post(
        "/generate/eventbrite",
        data={
            "event_id": "123",
            "eventbrite_token": "tok",
            "review": "true",
            "selected_emails": '["someone-else@example.com"]',
        },
    )
    assert r.status_code == 422
    assert "No attendees matched" in r.json().get("detail", "")

    r2 = client.post(
        "/generate/eventbrite",
        data={
            "event_id": "123",
            "eventbrite_token": "tok",
            "review": "true",
            "selected_emails": '["alice@example.com"]',
        },
    )
    assert r2.status_code == 200
    assert len(captured["attendees"]) == 1


def test_generate_eventbrite_send_reports_partial_failures(monkeypatch):
    class DummySMTP:
        def __init__(self, host, port):
            self.host = host
            self.port = port

        def starttls(self):
            return None

        def login(self, username, password):
            return None

        def send_message(self, msg):
            to_addr = str(msg.get("To", ""))
            if "alice@example.com" in to_addr:
                raise RuntimeError("smtp send failed")

        def quit(self):
            return None

    monkeypatch.setattr(httpx, "AsyncClient", DummyAsyncClient)
    monkeypatch.setattr(mod.smtplib, "SMTP", DummySMTP)
    monkeypatch.setattr(mod.smtplib, "SMTP_SSL", DummySMTP)
    monkeypatch.setattr(
        mod,
        "generate_batch",
        lambda *args, **kwargs: {
            "generated": [{"name": "Alice", "filename": "a.pdf", "pdf_bytes": b"pdf"}],
            "zip": b"",
            "email_jobs": [{"recipient": "alice@example.com", "pdf_bytes": b"pdf"}],
        },
    )

    client = TestClient(app)
    r = client.post(
        "/generate/eventbrite",
        data={
            "event_id": "123",
            "eventbrite_token": "tok",
            "send": "true",
            "review": "false",
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
        },
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload["status"] == "partial"
    assert payload["count"] == 0
    assert len(payload.get("failures", [])) == 1
