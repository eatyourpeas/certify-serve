# Certify Attendance Server

FastAPI wrapper around the `certify-attendance` package for generating attendance certificates (PDF), with:

- Single generation (`/generate`)
- CSV batch generation (`/generate/csv`)
- Eventbrite-driven generation and sending (`/generate/eventbrite`)
- Browser UI at `/` for previewing attendees, selecting recipients, generating ZIPs, and sending emails

## Quick Start

### 1. Configure environment

Copy the committed example template and fill values:

```bash
cp example.env .env
```

### 2. Run with Docker

```bash
docker compose up --build
```

Then open:

- UI: `http://localhost:8000/`
- Swagger: `http://localhost:8000/swagger`

## Self-Hosting Environment Variables

`example.env` includes the variables expected by the app.

### Required for Eventbrite workflow

- `EVENTBRITE_TOKEN`

### Required for email sending (when `send=true`)

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`

### Recommended sender defaults

- `FROM_NAME` (default: `Conference Team`)
- `FROM_EMAIL` (default: `noreply@example.com`)

### Optional

- `SMTP_BACKEND=console` to print emails to logs instead of sending

## Frontend Workflow (Current UI)

The homepage now uses a 3-card form:

1. Eventbrite Credentials
2. Certificate Details
3. Email Details

Follow this flow:

1. Enter `event_id`
2. Leave Eventbrite API token blank to use server `EVENTBRITE_TOKEN`, or provide one to override
3. Click **Preview Event Metadata**
4. Review/override title, date, subtitle, location, logo
5. Review attendees table (sorted by surname, paginated 15 per page)
6. Select attendees via checkboxes
7. Choose:
   - **Generate ZIP for Selected**
   - **Send All Selected**

Delivery status is shown per row (`sending`, `sent`, `failed`).

## Env Defaults vs UI Overrides

### Eventbrite token

- Server fallback: `EVENTBRITE_TOKEN`
- UI override: Eventbrite API token field in the form
- If UI token is blank, backend uses env token

### SMTP credentials

- Server fallback: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
- UI override: Email card -> **Override SMTP server settings** (collapsible section)
- Only non-empty override fields are sent; blanks continue to use server env values

## API Endpoints

### `POST /generate`

Generate one certificate.

Required form fields:

- `first_name`
- `surname`
- `email`
- `conference_title`
- `conference_date`

Optional:

- `subtitle`
- `location`
- `logo` (file)
- `review` (default `true`)
- `send` (default `false`)
- SMTP fields and email fields when sending

Behavior:

- `review=true`: returns ZIP with certificate PDF
- `send=true`: sends email and returns JSON

### `POST /generate/csv`

Generate certificates from CSV.

Required:

- `csv_file`
- `conference_title`
- `conference_date`

Optional:

- `subtitle`, `location`, `logo`, `review`, `send`
- SMTP and email fields when sending

### `GET|POST /generate/eventbrite/preview`

Fetches Eventbrite event metadata to prefill certificate fields.

Required:

- `event_id`
- Eventbrite token via field or server env

Returns metadata such as title/date/subtitle/location.

### `GET|POST /generate/eventbrite/attendees`

Fetch attendees for an Eventbrite event.

Inputs:

- `event_id`
- Eventbrite token via field or server env
- Optional `status` filter: `attended`, `registered`, `declined`, `waitlisted`

Returns attendee list with profile fields used by the UI.

### `POST /generate/eventbrite`

Generate certificates (ZIP or send emails) from Eventbrite attendees.

Required:

- `event_id`
- Eventbrite token via field or server env

Optional:

- `conference_title`, `conference_date`, `subtitle`, `location`
- `logo` file
- `selected_emails` (JSON array of emails) to process a subset
- `review` (`true` -> ZIP)
- `send` (`true` -> SMTP delivery)
- `status` attendee filter
- `greeting_type`: `simple`, `title_and_full_name`, `personalized`
- SMTP and email fields

Send response includes partial-failure reporting:

- `status`: `sent` or `partial`
- `count`: sent count
- `total`: attempted count
- `failures`: list of `{email, error}`

## Eventbrite Metadata Mapping

- `name.text` -> `conference_title`
- `start.local` -> `conference_date`
- `summary` or `description.text` -> `subtitle`
- venue address/summary -> `location`

## Notes

- The app supports both `certify_attendance` and compatible `certify` module shapes.
- If no custom logo is uploaded, generator defaults are used.
- For local diagnosis of email sending, set `SMTP_BACKEND=console`.
