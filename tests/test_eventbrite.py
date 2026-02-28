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
            raise httpx.HTTPError(f"status={self.status_code}")


class DummyAsyncClient:
    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, params=None):
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
