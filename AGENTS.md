# Certify Attendance Server - Agent Documentation

## Project Overview

**Certify Attendance Server** is a FastAPI-based web service that wraps the `certify-attendance` PyPI package to generate attendance certificates as PDFs. It supports single certificate generation, batch processing via CSV uploads, and direct Eventbrite integration for automated certificate generation from event attendees.

### Core Capabilities
- Generate individual attendance certificates (PDF)
- Batch generate certificates from CSV files
- Integrate with Eventbrite API to fetch attendees and generate certificates automatically
- Optional email delivery via SMTP with personalized PDF attachments
- Review mode: Download ZIP of all generated certificates before sending

---

## Architecture

```
certify-serve/
├── src/certify_server/
│   ├── main.py              # FastAPI application with all endpoints
│   └── __init__.py
├── tests/
│   ├── test_eventbrite.py   # Eventbrite integration tests
│   └── test_server.py       # Server endpoint tests
├── Dockerfile               # Container configuration
├── docker-compose.yml       # Development orchestration
├── pyproject.toml           # Python dependencies
└── README.md                # User documentation
```

### Dependencies
- **FastAPI**: Web framework for API endpoints
- **httpx**: Async HTTP client for Eventbrite API calls
- **certify_attendance**: External PyPI package that handles PDF generation
- **smtplib**: Built-in Python module for email sending

---

## API Endpoints

### 1. POST `/generate` - Single Certificate Generation

Generate a certificate for one attendee.

**Form Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `first_name` | string | Yes | Attendee's first name |
| `surname` | string | Yes | Attendee's last name |
| `email` | string | Yes | Attendee's email address |
| `conference_title` | string | Yes | Name of the conference/event |
| `conference_date` | string | Yes | Event date |
| `subtitle` | string | No | Optional subtitle |
| `logo` | file | No | Custom logo image bytes |
| `review` | boolean | No (default: true) | If true, return ZIP for review |
| `send` | boolean | No (default: false) | If true, send emails via SMTP |

**SMTP Fields (required when `send=true`):**
- `smtp_host`: SMTP server hostname
- `smtp_port`: SMTP port (e.g., 587, 465)
- `smtp_username`: SMTP username
- `smtp_password`: SMTP password
- `from_name`: Sender name
- `from_email`: Sender email
- `subject`: Email subject line
- `body`: Email body text

**Response:**
- On `review=true` (default): Returns ZIP file containing PDF certificate(s)
- On `send=true`: Returns JSON `{"status": "sent", "count": N}`

---

### 2. POST `/generate/csv` - Batch Certificate Generation from CSV

Generate certificates for multiple attendees from a CSV file.

**Form Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `csv_file` | file | Yes | CSV file with attendee data |
| `conference_title` | string | Yes | Name of the conference/event |
| `conference_date` | string | Yes | Event date |
| `subtitle` | string | No | Optional subtitle |
| `logo` | file | No | Custom logo image bytes |
| `review` | boolean | No (default: true) | If true, return ZIP for review |
| `send` | boolean | No (default: false) | If true, send emails via SMTP |

**CSV Format Requirements:**
- Headers are normalized to lowercase
- Must include columns for attendee identification:
  - **Name column**: Either `name` (full name) or separate `first_name` + `surname`/`last` columns
  - **Email column**: `email`, `attendee_email`, or similar

**Supported CSV patterns:**
```csv
name,attendee_email
John Doe,john@example.com
Jane Smith,jane@example.com
```

```csv
first_name,surname,email
John,Doe,john@example.com
Jane,Smith,jane@example.com
```

**Response:** Same as `/generate` endpoint

---

### 3. POST `/generate/eventbrite` - Eventbrite Integration ⭐

Automatically fetch attendees from an Eventbrite event and generate certificates.

**Form Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_id` | string | Yes | Eventbrite event ID |
| `eventbrite_token` | string | Yes | Eventbrite API token |
| `review` | boolean | No (default: true) | If true, return ZIP for review |

**Eventbrite API Integration:**

The endpoint performs the following workflow:

1. **Fetch Event Details**
   - URL: `https://www.eventbriteapi.com/v3/events/{event_id}/`
   - Extracts event title from `name.text` field
   - Extracts event date from `start.local` field

2. **Fetch Attendees List**
   - URL: `https://www.eventbriteapi.com/v3/events/{event_id}/attendees/`
   - Iterates through all attendees in the response

3. **Extract Attendee Profiles**
   For each attendee, extracts:
   - `first_name`: From `profile.first_name`
   - `surname`: From `profile.last_name`
   - `email`: From `profile.email`

4. **Generate Certificates**
   - Calls internal `generate_batch()` function with extracted attendees
   - Returns ZIP file (if `review=true`) or status count (if `review=false`)

**Example Request:**
```bash
curl -X POST "http://localhost:8000/generate/eventbrite" \
  -F "event_id=123456789" \
  -F "eventbrite_token=YOUR_API_TOKEN" \
  -F "review=true"
```

**Response:**
- On `review=true`: Returns ZIP file containing all attendee certificates
- On `review=false`: Returns JSON `{"status": "ok", "count": N}`

---

## Eventbrite Workflow (Detailed)

### Prerequisites
1. **Eventbrite API Token**: Obtain from [Eventbrite Developer Portal](https://www.eventbrite.com/platform/api)
2. **Event ID**: Found in your Eventbrite event URL or dashboard

### Workflow Steps

```
┌─────────────────────┐
│  POST /generate/    │
│   eventbrite        │
└──────────┬──────────┘
           │
           │ event_id, eventbrite_token
           ▼
┌─────────────────────────────────────────────┐
│  Step 1: Fetch Event Details                │
│  GET https://www.eventbriteapi.com/v3/      │
│  events/{event_id}/                         │
└──────────┬──────────────────────────────────┘
           │
           │ event title, date
           ▼
┌─────────────────────────────────────────────┐
│  Step 2: Fetch Attendees List               │
│  GET https://www.eventbriteapi.com/v3/      │
│  events/{event_id}/attendees/               │
└──────────┬──────────────────────────────────┘
           │
           │ attendees array with profiles
           ▼
┌─────────────────────────────────────────────┐
│  Step 3: Extract Attendee Data              │
│  - first_name from profile.first_name       │
│  - surname from profile.last_name           │
│  - email from profile.email                 │
└──────────┬──────────────────────────────────┘
           │
           │ normalized attendees list
           ▼
┌─────────────────────────────────────────────┐
│  Step 4: Generate Certificates              │
│  Call generate_batch(attendees, title, date)│
│  Uses certify_attendance package            │
└──────────┬──────────────────────────────────┘
           │
           │ PDF bytes per attendee
           ▼
┌─────────────────────┐
│  Step 5: Return     │
│  - ZIP file (review)│
│  - Status count     │
└─────────────────────┘
```

### Data Mapping

| Eventbrite Field | Internal Format |
|------------------|-----------------|
| `name.text` | `conference_title` |
| `start.local` | `conference_date` |
| `profile.first_name` | `first_name` |
| `profile.last_name` | `surname` |
| `profile.email` | `email` |

---

## Generator Integration

The server dynamically discovers the PDF generator function from the `certify_attendance` package. It searches for these callable names in order:

1. `generate_certificates`
2. `generate_pdfs`
3. `render_certificates`
4. `generate`
5. `create_certificates`

If none match, it also looks for:
- Functions with "pdf" in the name
- Classes with `generate`, `create`, or `render` methods

### Generator Function Signature (Expected)
```python
def generate_certificates(
    attendees: List[Dict],
    title: str,
    date: str,
    subtitle: Optional[str] = None,
    logo: Optional[bytes] = None
) -> List[Tuple[str, bytes]]:
    """
    Args:
        attendees: List of attendee dicts with 'first_name', 'surname', 'email'
        title: Conference/event title
        date: Event date string
        subtitle: Optional subtitle
        logo: Optional logo image bytes
    
    Returns:
        List of tuples: [(email, pdf_bytes), ...]
    """
```

---

## Email Sending Workflow

When `send=true`, the server sends personalized emails with PDF attachments:

1. **SMTP Configuration**: Provided via form fields or environment variables
2. **Console Backend Mode**: Set `SMTP_BACKEND=console` to log emails instead of sending
3. **SSL/TLS Support**: Auto-detects SSL (port 465) vs STARTTLS (other ports)
4. **Email Template**: Customizable subject and body per request

### Console Debug Mode Example
```bash
export SMTP_BACKEND=console
# Emails will be printed to stdout instead of sent
```

---

## Testing

### Run Tests
```bash
# From project root
python -m pytest tests/
```

### Test Coverage
- `test_server.py`: Tests for `/generate` and `/generate/csv` endpoints
- `test_eventbrite.py`: Tests for Eventbrite integration endpoint

### Mocking Generator in Tests
The server provides compatibility helpers for testing:
- `create_certificate()`: Single certificate generation
- `generate_batch()`: Batch certificate generation

---

## Deployment

### Docker
```bash
# Build image
docker build -t certify-server .

# Run container
docker run -p 8000:8000 certify-server
```

### Environment Variables
| Variable | Description |
|----------|-------------|
| `SMTP_BACKEND` | Set to `console` for debug mode |

---

## Error Handling

- **HTTP 422**: Validation errors (missing required fields, invalid SMTP config)
- **HTTP 500**: Generator failures, Eventbrite API errors
- **RuntimeError**: Missing `certify_attendance` package or generator function

---

## Notes for Agents

1. The server relies on an external `certify_attendance` package that must be installed separately
2. Eventbrite API requires a valid OAuth token with event management permissions
3. When modifying the Eventbrite workflow, ensure backward compatibility with existing attendee data structure
4. The generator discovery mechanism is flexible to accommodate different package implementations
5. ZIP file naming convention: `{email_without_at_and_dots}.pdf` (e.g., `john_doe_example_com.pdf`)