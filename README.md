# TITAN (Threat Inteligence Tracking & Analysis Nexus) — Cyber Threat Intelligence Platform

A comprehensive threat intelligence platform designed for small businesses and personal use. TITAN helps you track, analyze, and manage security incidents, malware, phishing attacks, indicators of compromise (IOCs), and mitigation strategies.

## Features

### Core Functionality
- **Event Management**: Track security incidents with categorization by type (Phishing, Malware, Breach, Insider Threat, Vulnerability, Policy Violation)
- **Malware Tracking**: Document malware families, instances, and associated IOCs
- **Phishing Campaigns**: Track phishing attempts with sender, target, and subject details
- **IOC Repository**: Store and manage indicators of compromise (IPs, domains, hashes, URLs, emails, file paths)
- **Mitigation Planning**: Create and assign mitigation tasks linked to specific events
- **Status Tracking**: Monitor event lifecycle from Open → In Progress → Resolved with closed dates

### Analytics & Reporting
- **Interactive Dashboard**: Real-time metrics with 30/60/90-day filtering
- **Detailed Reports Page**: 
  - Custom date range selection
  - Events closed over time
  - Status distribution by event type
  - Severity analysis (Critical, High, Medium, Low)
  - Event type trends
  - IOC type distribution
  - Recent events table
- **Visual Charts**: Powered by Chart.js with dark-themed UI

### Data Management
- **Settings Area**: Database statistics, backup, export to JSON, clear all data
- **Temporal Tracking**: Event dates, detection dates, occurrence dates, and closed dates for accurate retroactive analysis
- **Relationship Mapping**: Link malware/phishing to events, IOCs to threats, and mitigations to incidents

## Requirements

- **Python**: 3.12 or higher
- **Dependencies**: See `requirements.txt`
  - FastAPI (web framework)
  - SQLAlchemy (ORM)
  - Uvicorn (ASGI server)
  - Jinja2 (templating)
  - python-multipart (form handling)

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd TITAN
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

1. **Start the server**:
   ```bash
   python main.py
   ```

   The server will start on `http://0.0.0.0:8000` with auto-reload enabled.

2. **Access the web interface**:
   - Local: `http://localhost:8000`
   - Network: `http://<your-ip>:8000` (accessible from other devices on your network)

3. **Stop the server**: Press `Ctrl+C` in the terminal

## Database

- **Location**: `./TITAN-data/titan.sqlite` (auto-created on first run)
- **Type**: SQLite (file-based, no separate database server required)
- **Schema**: Automatically initialized with tables for Events, Malware, Phishing, IOCs, and Mitigations
- **Migrations**: Lightweight schema updates run automatically on startup

### Custom Database Path
Set the environment variable to use a different location:
```bash
export TITAN_DB_PATH=/path/to/your/database.sqlite
python main.py
```

## Usage Guide

### Managing Events
1. Navigate to **Events** from the dashboard
2. Click **+ New Event** to create an incident
3. Fill in:
   - Title and description
   - Type (Phishing, Malware, Breach, etc.)
   - Severity (Critical, High, Medium, Low)
   - Status (Open, In Progress, Resolved)
   - Event Date (when it occurred)
   - Closed Date (when resolved)
4. Link malware, phishing campaigns, and mitigations to the event

### Adding Malware & Phishing
- From an event detail page, use **+ Add Malware** or **+ Add Phishing**
- Specify name, family, occurrence date, and description
- Add IOCs (indicators) to each threat instance

### Recording IOCs
- When viewing malware or phishing, click **+ IOC**
- Select type: IP, Domain, Hash, URL, Email, File Path
- Provide the indicator value and optional description/confidence

### Creating Mitigations
- From an event, click **+ Add Mitigation**
- Title the action, describe it, and assign to a team member
- Track mitigation progress as events evolve

### Viewing Reports
1. Click **📊 Reports** in the header
2. Select a custom date range (Start/End dates)
3. Click **Apply** to refresh all charts and the recent events table
4. Review:
   - Events closed timeline
   - Status breakdown by type
   - Severity distribution
   - Event trends and IOC patterns

### Settings & Maintenance
- Access **⚙️ Settings** to:
  - View database statistics
  - **Backup Database**: Download a copy of `titan.sqlite`
  - **Export Data**: Download all data as JSON
  - **Clear All Data**: Reset the database (use with caution)

## Project Structure

```
TITAN/
├── backend/
│   ├── api.py           # FastAPI routes and endpoints
│   ├── db_models.py     # SQLAlchemy models
│   ├── db_init.py       # Database initialization
│   └── __pycache__/
├── frontend/
│   ├── templates/       # Jinja2 HTML templates
│   │   ├── index.html
│   │   ├── reports.html
│   │   ├── settings.html
│   │   └── events/, malware/, phishing/, iocs/, mitigations/
│   └── static/
│       └── styles.css   # Dark-themed CSS
├── TITAN-data/
│   └── titan.sqlite     # Database (auto-created)
├── main.py              # Application entry point
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## API Endpoints

### Chart & Analytics APIs
- `GET /api/charts/event-status-summary?days=30` — Status breakdown
- `GET /api/charts/events-closed-timeline?start=YYYY-MM-DD&end=YYYY-MM-DD` — Closed events timeline
- `GET /api/charts/event-severity-distribution?days=30` — Severity counts
- `GET /api/charts/events-types-30days?days=30` — Event type distribution
- `GET /api/charts/status-by-type?days=30` — Stacked status per type
- `GET /api/charts/ioc-type-distribution?days=30` — IOC type breakdown
- `GET /api/reports/recent-events?days=30&limit=50` — Recent events JSON

### CRUD Endpoints
- Events: `/events`, `/events/{id}`, `/events/new`, `/events/{id}/edit`
- Malware: `/malware`, `/malware/{id}`, `/events/{event_id}/malware/new`
- Phishing: `/phishing`, `/phish/{id}`, `/events/{event_id}/phish/new`
- IOCs: `/iocs`, `/malware/{id}/ioc/new`, `/phish/{id}/ioc/new`
- Mitigations: `/mitigations`, `/events/{event_id}/mitigation/new`

## Tips

- **Sample Data**: Run `python test_data.py` to populate the database with example events for testing
- **Network Access**: The server listens on `0.0.0.0`, making it accessible to other devices on your network—ideal for team environments
- **Date Ranges**: Use custom date ranges in reports to analyze specific time periods or compliance windows
- **Regular Backups**: Use the Settings → Backup feature to preserve your threat intelligence data

## Contributing

This is a personal/small business tool. Feel free to fork and customize for your organization's specific needs.

## License

See repository for license details.

## Support

For issues or questions, open an issue in the repository.
