# Certify Attendance Server

[![Swagger Docs](https://img.shields.io/badge/Docs-Swagger-blue?logo=swagger)](/swagger)

FastAPI wrapper around the `certify-attendance` PyPI package to generate single or batch attendance certificates and optionally send them via SMTP.

Quick start (local):

1. Build the image:

```bash
docker build -t certify-server .
```

1. Run the container exposing port 8000:

```bash
docker run -p 8000:8000 certify-server
```

Development helper:

- Use the provided `s/dev` script to build and run the service via `docker compose` in detached mode. From the repository root run:

```bash
./s/dev
# follow logs:
docker compose logs -f
```

- To rebuild with no cache (clean build):

```bash
docker compose build --no-cache
docker compose up -d
```

Endpoints:

- `POST /generate` (multipart/form-data) - single attendee. Fields: `first_name`, `surname`, `email`, `conference_title`, `conference_date`. Optional `logo` file, `review` (bool), `send` (bool), SMTP settings when `send=true`.
- `POST /generate/csv` (multipart/form-data) - CSV upload with attendee rows. CSV headers will be lower-cased and must include columns with `first` (first name), `surname` or `last` (surname), and `email`.

Responses:

- If `review=true` (default), endpoints return a ZIP of generated PDFs for review.
- If `send=true`, the server will send emails (SMTP) with personalized PDF attachments.

Notes:

- The server attempts to locate a generator callable inside the `certify_attendance` package. If your package exposes a different API, you may need to adapt `src/certify_server/main.py` to call the correct function/class.

## Security

- **Enforce HTTPS**: In production enable TLS at the edge (reverse proxy or load balancer) and set `ENFORCE_HTTPS=true` in your environment to enable redirects and HSTS.
- **CORS**: Restrict `ALLOWED_ORIGINS` to known frontends; avoid `*` in production.
- **Rate limiting**: Tune `RATE_LIMIT` and `RATE_PERIOD` (defaults in `example.env`). For multi-instance deployments use a Redis-backed limiter.
- **Request size limits**: `MAX_BODY_SIZE` limits upload sizes (default 10MB).
- **Security headers**: The server adds basic headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) and `Strict-Transport-Security` when HTTPS is enforced.
- **Edge TLS & proxy headers**: Ensure your proxy sets `X-Forwarded-Proto: https` so the app can detect HTTPS.
- **Logging & monitoring**: Monitor 4xx/5xx spikes and failed authentication attempts; forward logs to a central store.

For a hardened production deployment consider adding a Web Application Firewall (WAF), CSP headers, and a centralized secrets store for SMTP credentials.

---------------------

## Environment variables

The server reads configuration from environment variables. Copy `example.env` to `.env` and edit with your values. Key variables:

- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD` — SMTP server for sending email.
- `FROM_NAME`, `FROM_EMAIL` — default sender for outgoing emails.
- `RATE_LIMIT` — requests per `RATE_PERIOD` per client IP (default `60`).
- `RATE_PERIOD` — seconds for the rate limit window (default `60`).
- `ALLOWED_ORIGINS` — CORS allowed origins (comma-separated). Avoid `*` in production.
- `MAX_BODY_SIZE` — maximum request body size in bytes (default `10485760`, 10MB).
- `ENFORCE_HTTPS` — when `true`, the app will redirect HTTP to HTTPS and enable HSTS.
- `HSTS_MAX_AGE` — HSTS max-age in seconds (default `31536000`).

Example:

```bash
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=secret
FROM_NAME="Conference Team"
FROM_EMAIL=noreply@example.com
RATE_LIMIT=60
RATE_PERIOD=60
ALLOWED_ORIGINS=http://localhost:3000
MAX_BODY_SIZE=10485760
ENFORCE_HTTPS=false
HSTS_MAX_AGE=31536000
```
