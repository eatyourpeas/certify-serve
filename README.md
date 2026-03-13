# Certify Attendance Server

FastAPI wrapper around the `certify-attendance` PyPI package to generate single or batch attendance certificates and optionally send them via SMTP.

Quick start (local):

1. Build the image:

```bash
docker build -t certify-server .
```

2. Run the container exposing port 8000:

```bash
docker run -p 8000:8000 certify-server
```

Endpoints:

- `POST /generate` (multipart/form-data) - single attendee. Fields: `first_name`, `surname`, `email`, `conference_title`, `conference_date`. Optional `logo` file, `review` (bool), `send` (bool), SMTP settings when `send=true`.
- `POST /generate/csv` (multipart/form-data) - CSV upload with attendee rows. CSV headers will be lower-cased and must include columns with `first` (first name), `surname` or `last` (surname), and `email`.

Responses:
- If `review=true` (default), endpoints return a ZIP of generated PDFs for review.
- If `send=true`, the server will send emails (SMTP) with personalized PDF attachments.

Notes:

- The server attempts to locate a generator callable inside the `certify_attendance` package. If your package exposes a different API, you may need to adapt `src/certify_server/main.py` to call the correct function/class.
