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
- `POST /generate/eventbrite` (multipart/form-data) - Eventbrite integration. Fields: `event_id`, `eventbrite_token`, `review` (bool, default `true`). Fetches all attendees from Eventbrite and generates certificates automatically.

Responses:

- If `review=true` (default), endpoints return a ZIP of generated PDFs for review.
- If `send=true`, the server will send emails (SMTP) with personalized PDF attachments.

Notes:

- The server attempts to locate a generator callable inside the `certify_attendance` package. If your package exposes a different API, you may need to adapt `src/certify_server/main.py` to call the correct function/class.

## Eventbrite Integration

### Prerequisites

1. **Eventbrite API Token**: Obtain from [Eventbrite Developer Portal](https://www.eventbrite.com/platform/api)
2. **Event ID**: Found in your Eventbrite event URL or dashboard
3. Set `EVENTBRITE_TOKEN` in your `.env` file

### Usage Example (Dry Run)

To generate certificates for all attendees without sending emails:

```bash
# Source .env to load EVENTBRITE_TOKEN
set -a; source .env; set +a

# Generate certificates as ZIP (review mode, no emails sent)
curl -X POST "http://localhost:8000/generate/eventbrite" \
  -F "event_id=1984053600729" \
  -F "eventbrite_token=$EVENTBRITE_TOKEN" \
  -F "review=true"
```

This will:
- Fetch event details (title, date) from Eventbrite
- Retrieve all attendees from the event
- Generate a PDF certificate for each attendee
- Return a ZIP file containing all certificates for download
- **Not send any emails** (default behavior)

### Workflow

1. Server fetches event details from Eventbrite API
2. Server retrieves all attendees from the event
3. For each attendee, extracts: first name, last name, email
4. Generates PDF certificates using the `certify_attendance` package
5. Returns ZIP file (if `review=true`) or status count (if `review=false`)

### Data Mapping

| Eventbrite Field | Certificate Field |
|------------------|-----------------|
| `name.text` | Conference title |
| `start.local` | Event date |
| `profile.first_name` | Attendee first name |
| `profile.last_name` | Attendee surname |
| `profile.email` | Attendee email |

### Sending Emails

To send certificates via email, add `send=true` and SMTP configuration fields:

```bash
curl -X POST "http://localhost:8000/generate/eventbrite" \
  -F "event_id=1984053600729" \
  -F "eventbrite_token=$EVENTBRITE_TOKEN" \
  -F "send=true" \
  -F "smtp_host=smtp.example.com" \
  -F "smtp_port=587" \
  -F "smtp_username=apikey" \
  -F "smtp_password=your_smtp_password" \
  -F "from_name=Conference Team" \
  -F "from_email=noreply@example.com" \
  -F "subject=Your attendance certificate" \
  -F "body=Thank you for attending. Please find your certificate attached."
```

**Email Fields:**

| Field | Default | Description |
|-------|---------|-------------|
| `smtp_host` | required when `send=true` | SMTP server hostname (e.g., `smtp.gmail.com`) |
| `smtp_port` | required when `send=true` | SMTP port (e.g., `587` for STARTTLS, `465` for SSL) |
| `smtp_username` | required when `send=true` | SMTP username or API key |
| `smtp_password` | required when `send=true` | SMTP password or API secret |
| `from_name` | `Conference Team` | Sender name displayed to recipients |
| `from_email` | `noreply@example.com` | Sender email address |
| `subject` | `Your attendance certificate` | Email subject line |
| `body` | `Please find your attendance certificate attached.` | Email body text |

**Console Debug Mode:**

Set `SMTP_BACKEND=console` in your `.env` file to log emails to stdout instead of sending them:

```bash
export SMTP_BACKEND=console
# Emails will be printed to terminal for review
```

### Cherry-Picking Attendees

By default, the endpoint generates certificates for **all registered attendees**. To generate certificates only for attendees who actually attended, you can filter by attendee status.

**Eventbrite Attendee Status Values:**

| Status | Description |
|--------|-------------|
| `attended` | Attendee actually attended the event |
| `registered` | Attendee registered but may not have attended |
| `declined` | Attendee declined the invitation |
| `waitlisted` | Attendee is on the waitlist |

**Filtering by Status:**

The Eventbrite API supports filtering attendees by status. To cherry-pick only attendees who attended:

```bash
curl -X POST "http://localhost:8000/generate/eventbrite" \
  -F "event_id=1984053600729" \
  -F "eventbrite_token=$EVENTBRITE_TOKEN" \
  -F "review=true" \
  -F "status=attended"
```

**Available Status Filters:**

- `attended` - Only attendees who actually attended
- `registered` - All registered attendees (default, no filter)
- `declined` - Attendees who declined
- `waitlisted` - Attendees on the waitlist

**Implementation:**

The server now supports the `status` form parameter. When provided, it passes the filter to the Eventbrite API:

```python
# In generate_eventbrite endpoint:
params = {}
if status:
    params["status"] = status
att = await client.get(base + "/attendees/", params=params)
```

Alternatively, you can use the `/generate/csv` endpoint with a pre-filtered CSV of attendees who attended.
