# Certify Attendance Server - Agent Documentation

## Project Overview

Certify Attendance Server is a FastAPI service for generating attendance certificates and optionally sending them by SMTP.

Primary user paths:

- Single certificate generation
- CSV batch generation
- Eventbrite-integrated generation with attendee selection
- Frontend workflow for previewing metadata, selecting attendees, and sending/generating

## Architecture

```
certify-serve/
├── src/certify_server/
│   ├── main.py
│   └── __init__.py
├── site/
│   └── index.html
├── tests/
│   ├── test_eventbrite.py
│   └── test_server.py
├── Dockerfile
├── docker-compose.yml
├── example.env
├── pyproject.toml
└── README.md
```

## Environment Model (Important)

### Self-hosting baseline

Operators are expected to copy `example.env` to `.env` and provide secrets there.

Core env vars:

- `EVENTBRITE_TOKEN`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `FROM_NAME`
- `FROM_EMAIL`
- `SMTP_BACKEND` (optional, `console` for debug)

### Override rules

- Eventbrite token:
  - Backend falls back to `EVENTBRITE_TOKEN`
  - UI token field overrides when non-empty
- SMTP credentials:
  - Backend falls back to SMTP env vars
  - UI "Override SMTP server settings" fields override only when non-empty

This behavior is intentional and should be preserved when modifying the frontend or endpoints.

## Frontend Workflow (site/index.html)

Current UX is attendee-first and selection-based:

1. Eventbrite Credentials card (event id, optional token, status filter)
2. Certificate Details card (title/date/subtitle/location/logo overrides)
3. Email Details card (sender/template/greeting + collapsible SMTP override)

Action flow:

1. Click **Preview Event Metadata**
2. Frontend calls `/generate/eventbrite/preview` and `/generate/eventbrite/attendees`
3. Attendees appear sorted by surname, paginated 15 per page
4. User selects rows
5. User triggers:
   - **Generate ZIP for Selected** (review mode)
   - **Send All Selected** (send mode)
6. Per-row delivery state is shown (`sending`, `sent`, `failed`)

## API Endpoints

### `POST /generate`

Single attendee certificate generation and optional send.

### `POST /generate/csv`

CSV batch generation and optional send.

### `GET|POST /generate/eventbrite/preview`

Fetches and returns event metadata used to prefill certificate details.

### `GET|POST /generate/eventbrite/attendees`

Returns normalized attendee rows, optional status filter.

### `POST /generate/eventbrite`

Core eventbrite generation/sending endpoint.

Supports:

- Event metadata fallback from Eventbrite
- Optional override fields (title/date/subtitle/location/logo)
- Optional attendee filtering by `selected_emails`
- Optional attendee status filtering
- `review=true` ZIP output
- `send=true` email sending with partial failure reporting (`status=partial`, `failures`)

## Email Behavior

- SMTP SSL on port 465, STARTTLS otherwise
- Logs to console when `SMTP_BACKEND=console`
- Personalized message interpolation based on `greeting_type`

## Testing Notes

Run tests:

```bash
python -m pytest tests/
```

Coverage highlights:

- Eventbrite preview + attendees endpoints
- Eventbrite selected attendee filtering
- Send partial-failure responses
- CSV/single generation paths

## Maintenance Guidelines

When changing Eventbrite or frontend workflow:

1. Keep env fallback + UI override semantics intact
2. Keep attendee selection flow stable (`selected_emails`)
3. Keep backward compatible route support for preview/attendees (GET/POST)
4. Update `README.md`, `AGENTS.md`, and `example.env` together
