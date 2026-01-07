from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import io
import csv
import json
from sqlalchemy import func, or_
from .db_init import get_session, DEFAULT_DB_PATH
from .db_models import Event, Malware, MalwareFamily, Phish, IOC, Mitigation, APT, EventStatus, EventType
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime
from typing import Optional, List

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "frontend" / "templates"
STATIC_DIR = Path(__file__).resolve().parent.parent / "frontend" / "static"

env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)

SETTINGS_PATH = DEFAULT_DB_PATH.parent / "titan_settings.json"
DEFAULT_SECURITY_EMAIL = "security@company.com"

def load_security_email() -> str:
    try:
        if SETTINGS_PATH.exists():
            data = json.loads(SETTINGS_PATH.read_text())
            return data.get("security_email", DEFAULT_SECURITY_EMAIL)
    except Exception:
        pass
    return DEFAULT_SECURITY_EMAIL

def save_security_email(email: str) -> None:
    try:
        SETTINGS_PATH.write_text(json.dumps({"security_email": email}, indent=2))
    except Exception:
        pass

app = FastAPI(title="TITAN CTI Platform")

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/api/charts/malware-over-time")
async def malware_over_time(days: int = 30, start: Optional[str] = None, end: Optional[str] = None):
    """Malware counts per day within window or custom range"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    items = session.query(Malware).all()
    from collections import defaultdict
    timeline = defaultdict(int)
    for m in items:
        dt = m.occurrence_date if m.occurrence_date else m.created_at
        if window_start <= dt < window_end:
            key = dt.strftime('%Y-%m-%d')
            timeline[key] += 1
    labels = sorted(timeline.keys())
    data = [timeline[l] for l in labels]
    return {"labels": labels, "data": data}


@app.get("/api/charts/malware-by-family")
async def malware_by_family(days: int = 30, start: Optional[str] = None, end: Optional[str] = None, top: int = 10):
    """Top malware families within window"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    items = session.query(Malware).all()
    counts = {}
    for m in items:
        dt = m.occurrence_date if m.occurrence_date else m.created_at
        if window_start <= dt < window_end:
            name = (m.family_ref.name if m.family_ref else (m.family or '')).strip()
            if name:
                counts[name] = counts.get(name, 0) + 1
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top]
    labels = [k for k,_ in sorted_items]
    data = [v for _,v in sorted_items]
    return {"labels": labels, "data": data}


@app.get("/api/charts/malware-by-linkage")
async def malware_by_linkage(days: int = 30, start: Optional[str] = None, end: Optional[str] = None):
    """Counts of active malware (linked to open/in-progress events) vs other within window."""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    items = session.query(Malware).all()
    active = 0
    other = 0
    for m in items:
        dt = m.occurrence_date if m.occurrence_date else m.created_at
        if window_start <= dt < window_end:
            ev = m.event
            if ev and ev.status in (EventStatus.OPEN, EventStatus.IN_PROGRESS):
                active += 1
            else:
                other += 1
    return {"labels": ["Active (linked to open/in progress)", "Inactive"], "data": [active, other]}


def db_counts(session):
    return {
        "events": session.query(func.count(Event.id)).scalar() or 0,
        "malware": session.query(func.count(Malware.id)).scalar() or 0,
        "phishing": session.query(func.count(Phish.id)).scalar() or 0,
        "iocs": session.query(func.count(IOC.id)).scalar() or 0,
        "mitigations": session.query(func.count(Mitigation.id)).scalar() or 0,
        "apts": session.query(func.count(APT.id)).scalar() or 0,
        "events_open": session.query(func.count(Event.id)).filter(Event.status != EventStatus.RESOLVED).scalar() or 0,
    }


def get_critical_events(session):
    """Get critical events that are open or in progress"""
    return session.query(Event).filter(
        Event.severity == 'critical',
        Event.status.in_([EventStatus.OPEN, EventStatus.IN_PROGRESS])
    ).order_by(Event.detected_date.desc()).limit(5).all()


def get_recent_events(session, limit=3):
    """Get the most recently created events"""
    return session.query(Event).order_by(Event.created_at.desc()).limit(limit).all()


def get_risk_score(session):
    """Calculate a simple risk score from active events (open or in progress)."""
    weights = {"critical": 5, "high": 3, "medium": 2, "low": 1}
    active_events = session.query(Event).filter(Event.status.in_([EventStatus.OPEN, EventStatus.IN_PROGRESS])).all()
    score = 0
    for ev in active_events:
        sev = (ev.severity or "").strip().lower()
        score += weights.get(sev, 0)

    # Derive level from score
    if score == 0:
        level = "low"
    elif score <= 6:
        level = "low"
    elif score <= 14:
        level = "medium"
    elif score <= 25:
        level = "high"
    else:
        level = "critical"

    open_count = sum(1 for ev in active_events if ev.status == EventStatus.OPEN)
    in_progress_count = sum(1 for ev in active_events if ev.status == EventStatus.IN_PROGRESS)

    return {
        "score": score,
        "level": level.title(),
        "level_class": level,  # for badge class mapping
        "active_events": len(active_events),
        "open": open_count,
        "in_progress": in_progress_count,
    }


def parse_date(value: Optional[str]):
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    # Support both ISO and common UK formats
    fmts = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%d/%m/%Y",
        "%d/%m/%Y %H:%M",
        "%d-%m-%Y",
        "%d-%m-%Y %H:%M",
    ]
    for fmt in fmts:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def normalize_row(row: dict) -> dict:
    """Normalize CSV DictReader row keys (strip BOM/whitespace, lower-case).

    Ensures headers like '\ufeffname' or ' Name ' map to 'name'.
    """
    if not row:
        return {}
    normalized = {}
    for k, v in row.items():
        if k is None:
            # Skip rows that DictReader may produce with None keys
            continue
        nk = k.replace("\ufeff", "").strip().lower()
        normalized[nk] = v
    return normalized


def get_or_create_family(session, name: Optional[str]) -> Optional[MalwareFamily]:
    """Return an existing MalwareFamily (case-insensitive) or create it."""
    if not name:
        return None
    normalized = name.strip()
    if not normalized:
        return None
    existing = (
        session.query(MalwareFamily)
        .filter(MalwareFamily.name.ilike(normalized))
        .first()
    )
    if existing:
        return existing
    fam = MalwareFamily(name=normalized)
    session.add(fam)
    session.flush()  # assign id without full commit
    return fam


@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    session = get_session(DEFAULT_DB_PATH)
    counts = db_counts(session)
    critical_events = get_critical_events(session)
    recent_events = get_recent_events(session)
    risk_score = get_risk_score(session)
    template = env.get_template("index.html")
    return template.render(
        request=request,
        title="TITAN — Cyber Threat Intelligence",
        counts=counts,
        critical_events=critical_events,
        recent_events=recent_events,
        risk_score=risk_score,
        db_path=str(DEFAULT_DB_PATH),
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/charts/events-timeline")
async def events_timeline(days: int = 30):
    """Get event counts by status for the last N days (default 30)"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    thirty_days_ago = datetime.utcnow() - timedelta(days=days)
    
    # Fetch all events (we'll filter based on occurrence date or created_at)
    events = session.query(Event).all()
    
    # Group by date
    from collections import defaultdict
    timeline = defaultdict(lambda: {"open": 0, "in_progress": 0, "resolved": 0})
    
    for event in events:
        # Use event_date if available, otherwise fall back to created_at
        date_to_use = event.event_date if event.event_date else event.created_at
        
        # Only include events from the last 30 days
        if date_to_use >= thirty_days_ago:
            date_key = date_to_use.strftime('%Y-%m-%d')
            if event.status == EventStatus.OPEN:
                timeline[date_key]["open"] += 1
            elif event.status == EventStatus.IN_PROGRESS:
                timeline[date_key]["in_progress"] += 1
            elif event.status == EventStatus.RESOLVED:
                timeline[date_key]["resolved"] += 1
    
    # Convert to sorted list
    sorted_dates = sorted(timeline.keys())
    return {
        "labels": sorted_dates,
        "open": [timeline[d]["open"] for d in sorted_dates],
        "in_progress": [timeline[d]["in_progress"] for d in sorted_dates],
        "resolved": [timeline[d]["resolved"] for d in sorted_dates]
    }


@app.get("/api/charts/events-closed-timeline")
async def events_closed_timeline(days: int = 30, start: Optional[str] = None, end: Optional[str] = None):
    """Get counts of events closed per day within the last N days"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    events = session.query(Event).all()

    from collections import defaultdict
    timeline = defaultdict(int)

    for e in events:
        if e.closed_date and (window_start <= e.closed_date < window_end):
            key = e.closed_date.strftime('%Y-%m-%d')
            timeline[key] += 1

    labels = sorted(timeline.keys())
    data = [timeline[d] for d in labels]
    return {"labels": labels, "data": data}


@app.get("/api/charts/malware-phish-30days")
async def malware_phish_30days(days: int = 30, start: Optional[str] = None, end: Optional[str] = None):
    """Get malware and phishing counts over time within a window or custom range"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    malware_list = session.query(Malware).all()
    phish_list = session.query(Phish).all()

    from collections import defaultdict
    timeline = defaultdict(lambda: {"malware": 0, "phishing": 0})

    for malware in malware_list:
        date_to_use = malware.occurrence_date if malware.occurrence_date else malware.created_at
        if window_start <= date_to_use < window_end:
            date_key = date_to_use.strftime('%Y-%m-%d')
            timeline[date_key]["malware"] += 1

    for phish in phish_list:
        date_to_use = phish.occurrence_date if phish.occurrence_date else phish.created_at
        if window_start <= date_to_use < window_end:
            date_key = date_to_use.strftime('%Y-%m-%d')
            timeline[date_key]["phishing"] += 1

    sorted_dates = sorted(timeline.keys())
    return {
        "labels": sorted_dates,
        "malware": [timeline[d]["malware"] for d in sorted_dates],
        "phishing": [timeline[d]["phishing"] for d in sorted_dates]
    }


@app.get("/api/charts/phish-over-time")
async def phish_over_time(days: int = 30, start: Optional[str] = None, end: Optional[str] = None):
    """Phishing counts per day within window or custom range"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    items = session.query(Phish).all()
    from collections import defaultdict
    timeline = defaultdict(int)
    for p in items:
        dt = p.occurrence_date if p.occurrence_date else p.created_at
        if window_start <= dt < window_end:
            key = dt.strftime('%Y-%m-%d')
            timeline[key] += 1
    labels = sorted(timeline.keys())
    data = [timeline[l] for l in labels]
    return {"labels": labels, "data": data}


@app.get("/api/charts/phish-by-sender-domain")
async def phish_by_sender_domain(days: int = 30, start: Optional[str] = None, end: Optional[str] = None, top: int = 10):
    """Top sender domains for phishing within window"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    items = session.query(Phish).all()
    counts = {}
    for p in items:
        dt = p.occurrence_date if p.occurrence_date else p.created_at
        if window_start <= dt < window_end:
            sender = (p.sender or '').strip()
            dom = sender.split('@')[-1].lower() if '@' in sender else sender.lower()
            if dom:
                counts[dom] = counts.get(dom, 0) + 1
    # Sort and take top
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top]
    labels = [k for k,_ in sorted_items]
    data = [v for _,v in sorted_items]
    return {"labels": labels, "data": data}


@app.get("/api/charts/phish-by-target")
async def phish_by_target(days: int = 30, start: Optional[str] = None, end: Optional[str] = None, top: int = 10):
    """Top targeted recipients for phishing within window"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    items = session.query(Phish).all()
    counts = {}
    for p in items:
        dt = p.occurrence_date if p.occurrence_date else p.created_at
        if window_start <= dt < window_end:
            tgt = (p.target or '').strip().lower()
            if tgt:
                counts[tgt] = counts.get(tgt, 0) + 1
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top]
    labels = [k for k,_ in sorted_items]
    data = [v for _,v in sorted_items]
    return {"labels": labels, "data": data}


@app.get("/api/charts/threats-30days")
async def threats_30days(days: int = 30):
    """Get counts of events by type for the last 30 days (Threats view)"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    thirty_days_ago = datetime.utcnow() - timedelta(days=days)

    events = session.query(Event).all()

    type_counts = {t.value.replace('_', ' ').title(): 0 for t in EventType}

    for e in events:
        date_to_use = e.event_date if e.event_date else e.created_at
        if date_to_use >= thirty_days_ago:
            label = (e.type.value.replace('_', ' ').title() if e.type else 'Other')
            if label not in type_counts:
                type_counts[label] = 0
            type_counts[label] += 1

    labels = list(type_counts.keys())
    data = [type_counts[l] for l in labels]
    return {"labels": labels, "data": data}


@app.get("/api/charts/event-severity-distribution")
async def event_severity_distribution(days: int = 30, start: Optional[str] = None, end: Optional[str] = None):
    """Get event severity distribution for last N days"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    events = session.query(Event).all()

    severity_labels = [
        "Critical", "High", "Medium", "Low", "Unknown"
    ]
    counts = {label: 0 for label in severity_labels}

    for e in events:
        date_to_use = e.event_date if e.event_date else e.created_at
        if window_start <= date_to_use < window_end:
            sev = (e.severity or "Unknown").strip().lower()
            if sev == "critical":
                counts["Critical"] += 1
            elif sev == "high":
                counts["High"] += 1
            elif sev == "medium":
                counts["Medium"] += 1
            elif sev == "low":
                counts["Low"] += 1
            else:
                counts["Unknown"] += 1

    labels = list(counts.keys())
    data = [counts[l] for l in labels]
    return {"labels": labels, "data": data}


@app.get("/api/charts/status-by-type")
async def status_by_type(days: int = 30, start: Optional[str] = None, end: Optional[str] = None):
    """Return stacked counts of statuses per event type for last N days"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    events = session.query(Event).all()

    type_labels = [t.value.replace('_', ' ').title() for t in EventType]
    # Initialize per-type counts for each status
    open_counts = {label: 0 for label in type_labels}
    inprog_counts = {label: 0 for label in type_labels}
    resolved_counts = {label: 0 for label in type_labels}

    for e in events:
        date_to_use = e.event_date if e.event_date else e.created_at
        if window_start <= date_to_use < window_end:
            label = (e.type.value.replace('_', ' ').title() if e.type else 'Other')
            if e.status == EventStatus.OPEN:
                open_counts[label] = open_counts.get(label, 0) + 1
            elif e.status == EventStatus.IN_PROGRESS:
                inprog_counts[label] = inprog_counts.get(label, 0) + 1
            elif e.status == EventStatus.RESOLVED:
                resolved_counts[label] = resolved_counts.get(label, 0) + 1

    labels = type_labels
    datasets = [
        {"label": "Open", "data": [open_counts[l] for l in labels]},
        {"label": "In Progress", "data": [inprog_counts[l] for l in labels]},
        {"label": "Resolved", "data": [resolved_counts[l] for l in labels]},
    ]
    return {"labels": labels, "datasets": datasets}


@app.get("/api/reports/recent-events")
async def recent_events(days: int = 30, limit: int = 50, start: Optional[str] = None, end: Optional[str] = None):
    """Return recent events within the window"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    events = session.query(Event).all()

    def label_type(e):
        return (e.type.value.replace('_', ' ').title() if e.type else 'Other')

    def label_status(e):
        return e.status.value.replace('_', ' ').title()

    items = []
    for e in events:
        date_to_use = e.event_date if e.event_date else e.created_at
        if window_start <= date_to_use < window_end:
            items.append({
                "id": e.id,
                "title": e.title,
                "type": label_type(e),
                "severity": (e.severity or 'Unknown').title(),
                "status": label_status(e),
                "date": date_to_use.strftime('%Y-%m-%d %H:%M')
            })

    items.sort(key=lambda x: x["date"], reverse=True)
    return {"items": items[:limit]}


@app.get("/api/charts/ioc-type-distribution")
async def ioc_type_distribution(days: int = 30, start: Optional[str] = None, end: Optional[str] = None):
    """Distribution of IOC types created within the last N days or a custom range"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    if start:
        try:
            window_start = datetime.strptime(start, '%Y-%m-%d')
        except ValueError:
            pass
    if end:
        try:
            window_end = datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            pass

    iocs = session.query(IOC).all()
    counts = {}
    for i in iocs:
        if i.created_at and (window_start <= i.created_at < window_end):
            key = (i.type or 'Unknown').strip().title()
            counts[key] = counts.get(key, 0) + 1

    labels = list(counts.keys())
    data = [counts[l] for l in labels]
    return {"labels": labels, "data": data}


@app.get("/reports", response_class=HTMLResponse)
async def reports(request: Request):
    """Render the detailed reports page"""
    session = get_session(DEFAULT_DB_PATH)
    counts = db_counts(session)
    template = env.get_template("reports.html")
    return template.render(
        request=request,
        title="TITAN — Reports",
        counts=counts,
        db_path=str(DEFAULT_DB_PATH),
    )


@app.get("/api/reports/generate")
async def generate_report(audience: str, period_type: str, period: str):
    """Generate a customized report based on audience and time period"""
    from datetime import timedelta
    
    if audience not in ["exec", "it", "users"]:
        return {"error": "Invalid audience. Choose from: exec, it, users"}, 400
    
    if period_type not in ["month", "quarter", "year"]:
        return {"error": "Invalid period_type. Choose from: month, quarter, year"}, 400
    
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = None
    window_end = now
    period_label = ""
    
    if period_type == "month":
        # period should be MM (01-12)
        try:
            month_num = int(period)
            if not (1 <= month_num <= 12):
                return {"error": "Invalid month. Use 01-12"}, 400
            # Get current year and the specified month
            current_year = now.year
            window_start = datetime(current_year, month_num, 1)
            # Calculate next month for end
            if month_num == 12:
                window_end = datetime(current_year + 1, 1, 1)
            else:
                window_end = datetime(current_year, month_num + 1, 1)
            month_names = ['', 'January', 'February', 'March', 'April', 'May', 'June',
                          'July', 'August', 'September', 'October', 'November', 'December']
            period_label = f"{month_names[month_num]} {current_year}"
        except (ValueError, IndexError):
            return {"error": "Invalid month format"}, 400
    
    elif period_type == "quarter":
        # period should be Q1, Q2, Q3, or Q4
        try:
            current_year = now.year
            if period not in ["Q1", "Q2", "Q3", "Q4"]:
                return {"error": "Invalid quarter. Use Q1, Q2, Q3, or Q4"}, 400
            
            quarter_month_map = {
                "Q1": (1, 4),
                "Q2": (4, 7),
                "Q3": (7, 10),
                "Q4": (10, 13)  # Will handle year transition below
            }
            start_month, end_month = quarter_month_map[period]
            window_start = datetime(current_year, start_month, 1)
            
            if end_month == 13:
                window_end = datetime(current_year + 1, 1, 1)
            else:
                window_end = datetime(current_year, end_month, 1)
            
            period_label = f"{period} {current_year}"
        except (ValueError, KeyError):
            return {"error": "Invalid quarter format"}, 400
    
    elif period_type == "year":
        # period should be YYYY
        try:
            year = int(period)
            if not (2000 <= year <= 2100):
                return {"error": "Invalid year range"}, 400
            window_start = datetime(year, 1, 1)
            window_end = datetime(year + 1, 1, 1)
            period_label = str(year)
        except ValueError:
            return {"error": "Invalid year format"}, 400
    
    # Fetch events that either occurred or were created in the window
    events = session.query(Event).filter(
        ((Event.created_at >= window_start) & (Event.created_at < window_end)) |
        ((Event.event_date != None) & (Event.event_date >= window_start) & (Event.event_date < window_end))
    ).all()

    def event_in_window(ev):
        if ev.event_date:
            return window_start <= ev.event_date < window_end
        return window_start <= ev.created_at < window_end

    events_in_window = [e for e in events if event_in_window(e)]
    
    # Fetch malware/phishing instances that intersect with the window (initial SQL filter),
    # then constrain by primary timeline date: occurrence_date if present, else created_at.
    malware_raw = session.query(Malware).filter(
        ((Malware.created_at >= window_start) & (Malware.created_at < window_end)) |
        ((Malware.occurrence_date >= window_start) & (Malware.occurrence_date < window_end))
    ).all()
    phishing_raw = session.query(Phish).filter(
        ((Phish.created_at >= window_start) & (Phish.created_at < window_end)) |
        ((Phish.occurrence_date >= window_start) & (Phish.occurrence_date < window_end))
    ).all()
    
    def in_window(dt):
        return (dt is not None) and (window_start <= dt < window_end)
    
    def malware_date(m):
        return m.occurrence_date if m.occurrence_date else m.created_at
    
    def phish_date(p):
        return p.occurrence_date if p.occurrence_date else p.created_at
    
    malware_items = [m for m in malware_raw if in_window(malware_date(m))]
    phishing_items = [p for p in phishing_raw if in_window(phish_date(p))]
    
    # Count summary statistics
    total_events = len(events_in_window)  # New events in this period (by event_date when present)
    # Include open/in-progress events that may have been created before the period but are still active
    open_events = session.query(Event).filter(
        Event.status.in_([EventStatus.OPEN, EventStatus.IN_PROGRESS]),
        Event.created_at < window_end
    ).count()
    resolved_events = len([e for e in events_in_window if e.status == EventStatus.RESOLVED])
    in_progress_events = len([e for e in events_in_window if e.status == EventStatus.IN_PROGRESS])
    
    critical_events = len([e for e in events_in_window if e.severity == "critical"])
    high_events = len([e for e in events_in_window if e.severity == "high"])
    medium_events = len([e for e in events_in_window if e.severity == "medium"])
    low_events = len([e for e in events_in_window if e.severity == "low"])
    
    total_malware = len(malware_items)
    total_phishing = len(phishing_items)
    
    # Get severity distribution
    severity_counts = {}
    for event in events_in_window:
        sev = event.severity or "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    # Get event type distribution
    event_type_counts = {}
    for event in events_in_window:
        et = str(event.type.value) if event.type else "unknown"
        event_type_counts[et] = event_type_counts.get(et, 0) + 1
    
    # Get top malware families
    malware_families = {}
    for m in malware_items:
        family_name = (m.family_ref.name if m.family_ref else (m.family or 'Unknown')).strip()
        malware_families[family_name] = malware_families.get(family_name, 0) + 1
    top_malware = sorted(malware_families.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Get top phishing senders
    phishing_senders = {}
    for p in phishing_items:
        sender = (p.sender or 'Unknown').strip()
        phishing_senders[sender] = phishing_senders.get(sender, 0) + 1
    top_senders = sorted(phishing_senders.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Calculate day-by-day trends within the period for visualization
    from collections import defaultdict
    daily_malware = defaultdict(int)
    daily_phishing = defaultdict(int)
    for m in malware_items:
        dt = malware_date(m)
        day_key = dt.strftime('%Y-%m-%d')
        daily_malware[day_key] += 1
    for p in phishing_items:
        dt = phish_date(p)
        day_key = dt.strftime('%Y-%m-%d')
        daily_phishing[day_key] += 1
    
    # Get top targeted areas/departments
    targeted_areas = {}
    for p in phishing_items:
        target = (p.target or 'Unknown').strip()
        targeted_areas[target] = targeted_areas.get(target, 0) + 1
    top_targets = sorted(targeted_areas.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Get associated APTs
    apt_associations = {}
    for event in events_in_window:
        for apt in event.apts:
            apt_name = apt.name
            apt_associations[apt_name] = apt_associations.get(apt_name, 0) + 1
    for m in malware_items:
        for apt in m.apts:
            apt_name = apt.name
            apt_associations[apt_name] = apt_associations.get(apt_name, 0) + 1
    for p in phishing_items:
        for apt in p.apts:
            apt_name = apt.name
            apt_associations[apt_name] = apt_associations.get(apt_name, 0) + 1
    
    top_apts = sorted(apt_associations.items(), key=lambda x: x[1], reverse=True)[:5]
    
    security_email = load_security_email()
    
    # Generate HTML report based on audience
    if audience == "exec":
        html = generate_executive_report(period_label, period_type, total_events, open_events, resolved_events, 
                                         critical_events, high_events, total_malware, 
                                         total_phishing, severity_counts, top_malware, top_senders,
                                         daily_malware, daily_phishing, top_targets, top_apts)
    elif audience == "it":
        html = generate_it_report(period_label, total_events, open_events, resolved_events, in_progress_events,
                                  critical_events, high_events, medium_events, low_events,
                                  total_malware, total_phishing, event_type_counts, top_malware, 
                                  top_senders, malware_items, phishing_items)
    else:  # users
        html = generate_users_report(period_label, total_events, resolved_events, critical_events, 
                                     high_events, total_phishing, security_email)
    
    return {"html": html}


def generate_executive_report(period_label, period_type, total_events, open_events, resolved_events, critical_events,
                              high_events, total_malware, total_phishing, severity_counts, 
                              top_malware, top_senders, daily_malware, daily_phishing, 
                              top_targets, top_apts):
    """Generate executive summary report"""
    
    # Generate trend visualization data only for quarter and year reports
    trend_chart_html = ""
    if period_type in ["quarter", "year"]:
        # Generate trend visualization data - sorted by date
        dates_sorted = sorted(daily_malware.keys() | daily_phishing.keys())
        trend_data = []
        for date in dates_sorted:
            trend_data.append({
                'date': date,
                'malware': daily_malware.get(date, 0),
                'phishing': daily_phishing.get(date, 0)
            })
        
        # Create SVG-based trend chart
        trend_chart_html = generate_trend_chart(trend_data)
    
    severity_html = "".join([
        f"<div class='metric'><div class='metric-value'>{count}</div><div class='metric-label'>{sev.title()}</div></div>"
        for sev, count in sorted(severity_counts.items())
    ])
    
    malware_html = "".join([
        f"<tr><td>{family}</td><td style='text-align: center;'>{count}</td></tr>"
        for family, count in top_malware
    ]) if top_malware else "<tr><td colspan='2' style='text-align: center;'>No malware detected</td></tr>"
    
    sender_html = "".join([
        f"<tr><td>{sender}</td><td style='text-align: center;'>{count}</td></tr>"
        for sender, count in top_senders
    ]) if top_senders else "<tr><td colspan='2' style='text-align: center;'>No phishing detected</td></tr>"
    
    targets_html = "".join([
        f"<tr><td>{target}</td><td style='text-align: center;'>{count}</td></tr>"
        for target, count in top_targets
    ]) if top_targets else "<tr><td colspan='2' style='text-align: center;'>No targeting data</td></tr>"
    
    apts_html = ""
    if top_apts:
        for apt_name, count in top_apts:
            apts_html += f"""
            <div style="background-color: #fee; padding: 1rem; margin-bottom: 0.75rem; border-left: 4px solid #d93025; border-radius: 4px;">
              <div style="font-weight: bold; color: #d93025;">{apt_name}</div>
              <div style="font-size: 0.875rem; color: #1d1d1d;">Associated with {count} incident(s)</div>
            </div>
            """
    else:
        apts_html = "<p>No known APT associations detected</p>"
    
    # Build trend section only for quarter and year reports
    trend_section = ""
    if trend_chart_html:
        trend_section = f"""
    <h2>Threat Trend Analysis</h2>
    <div style="background-color: #f0f4f9; padding: 1.5rem; border-radius: 6px; margin: 1.5rem 0;">
      {trend_chart_html}
            <div style="font-size: 0.875rem; color: #1d1d1d; margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #ddd;">
        <p><strong>Trend Insight:</strong> This chart shows trends in malware detections and phishing attempts. Use this to identify seasonal patterns and assess the effectiveness of recent security measures.</p>
      </div>
    </div>"""
    
    return f"""
    <div class="report-header">
      <h1>Security Executive Report</h1>
      <p><strong>Report Period:</strong> {period_label}</p>
      <p><strong>Generated:</strong> {datetime.utcnow().strftime('%B %d, %Y at %I:%M %p UTC')}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p>This report provides a high-level overview of security incidents and threats detected within your organization for {period_label}.</p>
    
    <h2>Key Metrics</h2>
    <div style="display: flex; flex-wrap: wrap; gap: 2rem; margin: 1.5rem 0;">
      <div class="metric">
        <div class="metric-value">{total_events}</div>
                <div class="metric-label">New Events</div>
      </div>
      <div class="metric">
        <div class="metric-value" style="color: #d93025;">{open_events}</div>
        <div class="metric-label">Open Events</div>
      </div>
      <div class="metric">
        <div class="metric-value" style="color: #1e8e3e;">{resolved_events}</div>
        <div class="metric-label">Resolved Events</div>
      </div>
      <div class="metric">
        <div class="metric-value" style="color: #f9ab00;">{critical_events + high_events}</div>
        <div class="metric-label">Critical/High Priority</div>
      </div>
    </div>
    
    {trend_section}
    
    <h2>Threat Overview</h2>
    <div style="margin: 2rem 0;">
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin: 1.5rem 0;">
        <div>
          <p><strong>Malware Incidents:</strong> {total_malware}</p>
          <p><strong>Phishing Attempts:</strong> {total_phishing}</p>
        </div>
        <div>
          <p><strong>Severity Distribution:</strong></p>
          <div style="display: flex; gap: 1rem;">
            {severity_html}
          </div>
        </div>
      </div>
    </div>
    
    <h2>Most Targeted Areas/Departments</h2>
    <div style="margin: 2rem 0;">
      <table style="width: 100%; border-collapse: collapse;">
        <thead>
          <tr style="background-color: #1a73e8; color: white;">
            <th style="padding: 0.75rem; text-align: left;">Target Area/Department</th>
            <th style="padding: 0.75rem; text-align: center;">Incidents</th>
          </tr>
        </thead>
        <tbody>
          {targets_html}
        </tbody>
      </table>
    <p style="font-size: 0.875rem; color: #fff; margin-top: 1rem;"><strong>Note:</strong> These are the departments or groups most frequently targeted by phishing attacks. Consider enhanced security awareness training for these areas.</p>
    </div>
    
    <h2>Known Threat Actors (APTs)</h2>
    <div style="margin: 2rem 0;">
      <p>The following Advanced Persistent Threat (APT) groups have been identified as associated with incidents in your environment:</p>
      {apts_html}
    </div>
    
    <h2>Top Threats</h2>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin: 1.5rem 0;">
      <div>
        <h3 style="margin-top: 0;">Top Malware Families</h3>
        <table>
          <thead>
            <tr><th>Family</th><th style="text-align: center;">Count</th></tr>
          </thead>
          <tbody>
            {malware_html}
          </tbody>
        </table>
      </div>
      <div>
        <h3 style="margin-top: 0;">Top Phishing Senders</h3>
        <table>
          <thead>
            <tr><th>Sender</th><th style="text-align: center;">Count</th></tr>
          </thead>
          <tbody>
            {sender_html}
          </tbody>
        </table>
      </div>
    </div>
    
    <h2>Recommendations</h2>
    <ul>
      <li>Review open and unresolved security incidents for immediate action</li>
      <li>Increase monitoring for detected malware families and APT groups</li>
      <li>Implement targeted security awareness training for high-risk departments identified above</li>
      <li>Consider threat intelligence integration for early warning of APT activities</li>
      <li>Review and strengthen email security controls to reduce phishing attempts</li>
      <li>Develop incident response playbooks specific to identified APT tactics</li>
    </ul>
    """


def generate_trend_chart(trend_data):
    """Generate an SVG-based trend chart showing malware and phishing over time"""
    if not trend_data:
        return "<p style='text-align: center; color: #999;'>No trend data available</p>"
    
    # Calculate chart dimensions and scaling
    width = 600
    height = 300
    padding = 50
    chart_width = width - (padding * 2)
    chart_height = height - (padding * 2)
    
    # Find max value for scaling
    max_value = max([d['malware'] + d['phishing'] for d in trend_data] or [1])
    if max_value == 0:
        max_value = 10
    
    # Generate grid lines and labels
    grid_lines = ""
    y_labels = ""
    num_gridlines = 5
    for i in range(num_gridlines + 1):
        y = height - padding - (chart_height * i / num_gridlines)
        value = int((max_value * i) / num_gridlines)
        grid_lines += f'<line x1="{padding}" y1="{y}" x2="{width - padding}" y2="{y}" stroke="#e0e0e0" stroke-width="1"/>\n'
        y_labels += f'<text x="{padding - 10}" y="{y + 4}" text-anchor="end" font-size="12" fill="#666">{value}</text>\n'
    
    # Generate data points and bars
    points = []
    malware_points = []
    phishing_points = []
    
    x_step = chart_width / (len(trend_data) - 1) if len(trend_data) > 1 else chart_width
    bar_width = (x_step * 0.35)
    
    # Determine label format based on data (date vs month)
    use_short_dates = len(trend_data) > 12  # If more than 12 data points, use short date format
    
    for idx, data in enumerate(trend_data):
        x_base = padding + (idx * x_step)
        
        malware_height = (data['malware'] / max_value) * chart_height
        phishing_height = (data['phishing'] / max_value) * chart_height
        
        # Malware bar (left)
        malware_x = x_base - (bar_width / 2)
        malware_y = height - padding - malware_height
        points.append(f'<rect x="{malware_x}" y="{malware_y}" width="{bar_width}" height="{malware_height}" fill="#1a73e8" opacity="0.8"/>')
        
        # Phishing bar (right)
        phishing_x = x_base + (bar_width / 2)
        phishing_y = height - padding - phishing_height
        points.append(f'<rect x="{phishing_x}" y="{phishing_y}" width="{bar_width}" height="{phishing_height}" fill="#d93025" opacity="0.8"/>')
        
        # Date/label
        label_key = 'date' if 'date' in data else 'month'
        label_text = data[label_key]
        
        # For dates, show only every nth label to avoid crowding
        show_label = True
        if use_short_dates:
            # Show every 5th label
            show_label = (idx % 5 == 0 or idx == len(trend_data) - 1)
            if show_label and label_key == 'date':
                # Convert YYYY-MM-DD to MM/DD format
                label_text = '/'.join(label_text.split('-')[1:])
        
        if show_label:
            points.append(f'<text x="{x_base}" y="{height - padding + 20}" text-anchor="middle" font-size="11" fill="#333">{label_text}</text>')
    
    svg = f"""
        <div>
      <svg width="{width}" height="{height}" style="border: 1px solid #e0e0e0; border-radius: 4px; background-color: white; max-width: 100%;">
        <!-- Grid lines -->
        {grid_lines}
        
        <!-- Y-axis labels -->
        {y_labels}
        
        <!-- Y-axis line -->
        <line x1="{padding}" y1="{padding}" x2="{padding}" y2="{height - padding}" stroke="#333" stroke-width="2"/>
        
        <!-- X-axis line -->
        <line x1="{padding}" y1="{height - padding}" x2="{width - padding}" y2="{height - padding}" stroke="#333" stroke-width="2"/>
        
        <!-- Data bars -->
        {''.join(points)}
      </svg>
    </div>
    
    <!-- Legend -->
        <div style="margin-top: 1rem; display: flex; gap: 2rem;">
            <div style="display: flex; align-items: center; gap: 0.5rem; color: #1d1d1d;">
        <div style="width: 20px; height: 20px; background-color: #1a73e8; border-radius: 2px;"></div>
                <span style="color: #1d1d1d;">Malware Detections</span>
      </div>
            <div style="display: flex; align-items: center; gap: 0.5rem; color: #1d1d1d;">
        <div style="width: 20px; height: 20px; background-color: #d93025; border-radius: 2px;"></div>
                <span style="color: #1d1d1d;">Phishing Attempts</span>
      </div>
    </div>
    """
    
    return svg


def generate_it_report(period_label, total_events, open_events, resolved_events, in_progress_events,
                       critical_events, high_events, medium_events, low_events,
                       total_malware, total_phishing, event_type_counts, top_malware, 
                       top_senders, malware_items, phishing_items):
    """Generate detailed IT/Technical report"""
    
    event_type_html = "".join([
        f"<div class='metric'><div class='metric-value'>{count}</div><div class='metric-label'>{event_type.replace('_', ' ').title()}</div></div>"
        for event_type, count in sorted(event_type_counts.items())
    ]) if event_type_counts else "<p>No events</p>"
    
    malware_html = "".join([
        f"<tr><td>{family}</td><td style='text-align: center;'>{count}</td></tr>"
        for family, count in top_malware
    ]) if top_malware else "<tr><td colspan='2' style='text-align: center;'>No malware detected</td></tr>"
    
    sender_html = "".join([
        f"<tr><td>{sender}</td><td style='text-align: center;'>{count}</td></tr>"
        for sender, count in top_senders
    ]) if top_senders else "<tr><td colspan='2' style='text-align: center;'>No phishing detected</td></tr>"
    
    return f"""
    <div class="report-header">
      <h1>IT Security Incident Report</h1>
      <p><strong>Report Period:</strong> {period_label}</p>
      <p><strong>Generated:</strong> {datetime.utcnow().strftime('%B %d, %Y at %I:%M %p UTC')}</p>
    </div>
    
    <h2>Incident Summary</h2>
    <p>Detailed technical report of security incidents detected and handled during {period_label}.</p>
    
    <h2>Incident Statistics</h2>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1.5rem 0; color: #1d1d1d;">
            <div style="background-color: #f0f4f9; padding: 1rem; border-radius: 6px; color: #1d1d1d;">
                <div class="metric-value" style="color: #1d1d1d;">{total_events}</div>
                <div class="metric-label" style="color: #1d1d1d;">New Incidents</div>
            </div>
            <div style="background-color: #f0f4f9; padding: 1rem; border-radius: 6px; color: #1d1d1d;">
                <div class="metric-value" style="color: #d93025;">{open_events}</div>
                <div class="metric-label" style="color: #1d1d1d;">Open</div>
            </div>
            <div style="background-color: #f0f4f9; padding: 1rem; border-radius: 6px; color: #1d1d1d;">
                <div class="metric-value" style="color: #f9ab00;">{in_progress_events}</div>
                <div class="metric-label" style="color: #1d1d1d;">In Progress</div>
            </div>
            <div style="background-color: #f0f4f9; padding: 1rem; border-radius: 6px; color: #1d1d1d;">
                <div class="metric-value" style="color: #1e8e3e;">{resolved_events}</div>
                <div class="metric-label" style="color: #1d1d1d;">Resolved</div>
            </div>
        </div>
    
    <h2>Severity Breakdown</h2>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1.5rem 0; color: #1d1d1d;">
            <div style="background-color: #fce4e4; padding: 1rem; border-radius: 6px; border-left: 4px solid #d93025; color: #1d1d1d;">
                <div class="metric-value" style="color: #d93025;">{critical_events}</div>
                <div class="metric-label" style="color: #1d1d1d;">Critical</div>
            </div>
            <div style="background-color: #fef3c7; padding: 1rem; border-radius: 6px; border-left: 4px solid #f9ab00; color: #1d1d1d;">
                <div class="metric-value" style="color: #f9ab00;">{high_events}</div>
                <div class="metric-label" style="color: #1d1d1d;">High</div>
            </div>
            <div style="background-color: #fef3c7; padding: 1rem; border-radius: 6px; border-left: 4px solid #f9ab00; color: #1d1d1d;">
                <div class="metric-value" style="color: #f9ab00;">{medium_events}</div>
                <div class="metric-label" style="color: #1d1d1d;">Medium</div>
            </div>
            <div style="background-color: #e8f5e9; padding: 1rem; border-radius: 6px; border-left: 4px solid #1e8e3e; color: #1d1d1d;">
                <div class="metric-value" style="color: #1e8e3e;">{low_events}</div>
                <div class="metric-label" style="color: #1d1d1d;">Low</div>
            </div>
        </div>
    
    <h2>Incident Types</h2>
    <div style="display: flex; flex-wrap: wrap; gap: 1.5rem; margin: 1.5rem 0;">
      {event_type_html}
    </div>
    
    <h2>Threat Analysis</h2>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin: 1.5rem 0;">
      <div>
        <h3 style="margin-top: 0;">Malware Detection</h3>
        <p><strong>Total Malware Instances:</strong> {total_malware}</p>
        <h4>Top Families</h4>
        <table>
          <thead>
            <tr><th>Family</th><th style="text-align: center;">Count</th></tr>
          </thead>
          <tbody>
            {malware_html}
          </tbody>
        </table>
      </div>
      <div>
        <h3 style="margin-top: 0;">Phishing Detection</h3>
        <p><strong>Total Phishing Attempts:</strong> {total_phishing}</p>
        <h4>Top Sender Domains</h4>
        <table>
          <thead>
            <tr><th>Sender</th><th style="text-align: center;">Count</th></tr>
          </thead>
          <tbody>
            {sender_html}
          </tbody>
        </table>
      </div>
    </div>
    
    <h2>Recommended Actions</h2>
    <ul>
      <li>Prioritize resolution of critical and high-severity incidents</li>
      <li>Implement detection rules for identified malware families</li>
      <li>Update email filters and gateway rules for detected phishing senders</li>
      <li>Consider threat intelligence integration for automated defense</li>
      <li>Review and strengthen incident response procedures</li>
    </ul>
    """


def generate_users_report(period_label, total_events, resolved_events, critical_events, high_events, total_phishing, security_email):
    """Generate user-facing awareness report"""
    
    return f"""
    <div class="report-header">
      <h1>Security Awareness Report</h1>
      <p><strong>Report Period:</strong> {period_label}</p>
      <p><strong>Generated:</strong> {datetime.utcnow().strftime('%B %d, %Y')}</p>
    </div>
    
    <h2>Your Organization's Security Posture</h2>
    <p>This report highlights security threats and incidents detected in our organization during {period_label}. Your awareness and action are critical to our defense.</p>
    
    <h2>Key Threats Detected</h2>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin: 2rem 0;">
            <div style="background-color: #fce4e4; padding: 1.5rem; border-radius: 6px; border-left: 4px solid #d93025; color: #1f2937;">
                <h3 style="color: #d93025; margin-top: 0;">Phishing Attempts</h3>
                <p style="font-size: 2rem; font-weight: bold; color: #d93025; margin: 0.5rem 0;">{total_phishing}</p>
                <p style="color: #1f2937;">Suspicious emails detected and blocked during {period_label}.</p>
            </div>
            <div style="background-color: #fef3c7; padding: 1.5rem; border-radius: 6px; border-left: 4px solid #f9ab00; color: #1f2937;">
                <h3 style="color: #f9ab00; margin-top: 0;">Critical Alerts</h3>
                <p style="font-size: 2rem; font-weight: bold; color: #f9ab00; margin: 0.5rem 0;">{critical_events + high_events}</p>
                <p style="color: #1f2937;">High-priority security incidents requiring immediate attention.</p>
            </div>
        </div>
    
    <h2>What You Should Do</h2>
        <div style="margin: 2rem 0;">
      <h3 style="background-color: #e3f2fd; padding: 0.75rem 1rem; border-left: 4px solid #1a73e8; margin: 0; color: #0f172a;">Protect Yourself from Phishing</h3>
            <ul style="margin-top: 1rem;">
        <li><strong>Verify senders:</strong> Check email addresses carefully, even if they look legitimate</li>
        <li><strong>Hover before clicking:</strong> Hover over links to see the actual destination before clicking</li>
        <li><strong>Don't trust attachments:</strong> Unexpected attachments may contain malware</li>
        <li><strong>Report suspicious emails:</strong> Use your company-approved phishing reporting method.</li>
        <li><strong>Use multi-factor authentication:</strong> Enable MFA on all important accounts</li>
      </ul>
    </div>
    
    <h2>Password Security</h2>
    <ul>
      <li>Use unique, complex passwords for each account (12+ characters)</li>
      <li>Never share passwords with colleagues or write them down</li>
      <li>Change passwords immediately if you suspect compromise</li>
      <li>Use a password manager to store passwords securely</li>
    </ul>
    
    <h2>Contact Security Team</h2>
    <p>If you suspect a security incident or have questions about staying secure:</p>
    <ul>
      <li>Email: {security_email}</li>
      <li>Phone: Contact your IT helpdesk</li>
      <li>Report phishing: Use your company-approved reporting method.</li>
    </ul>
    
    <h2>Summary</h2>
    <p>During {period_label}, our organization has successfully detected and prevented {resolved_events} security incidents. Our collective vigilance makes this possible. Thank you for your continued commitment to security!</p>
    """


@app.get("/api/charts/events-by-start-date")
async def events_by_start_date(days: int = 30):
    """Return total event counts grouped by start date (event_date fallback to created_at) for last 30 days"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    thirty_days_ago = datetime.utcnow() - timedelta(days=days)

    events = session.query(Event).all()

    from collections import defaultdict
    timeline = defaultdict(int)

    for e in events:
        date_to_use = e.event_date if e.event_date else e.created_at
        if date_to_use >= thirty_days_ago:
            key = date_to_use.strftime('%Y-%m-%d')
            timeline[key] += 1

    labels = sorted(timeline.keys())
    data = [timeline[d] for d in labels]
    return {"labels": labels, "data": data}


@app.get("/api/charts/events-types-30days")
async def events_types_30days(days: int = 30):
    """Get event type counts for the last 30 days"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    thirty_days_ago = datetime.utcnow() - timedelta(days=days)

    # Fetch all events then filter by event_date/created_at
    events = session.query(Event).all()

    # Initialize counts for all known types to ensure consistent labels
    type_counts = {t.value.replace('_', ' ').title(): 0 for t in EventType}

    for e in events:
        date_to_use = e.event_date if e.event_date else e.created_at
        if date_to_use >= thirty_days_ago:
            label = (e.type.value.replace('_', ' ').title() if e.type else 'Other')
            # If a type is None, group under Other
            if label not in type_counts:
                type_counts[label] = 0
            type_counts[label] += 1

    labels = list(type_counts.keys())
    data = [type_counts[l] for l in labels]
    return {"labels": labels, "data": data}


@app.get("/api/charts/event-status-summary")
async def event_status_summary(days: int = 30):
    """Get event status breakdown for the last N days (default 30)"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    thirty_days_ago = datetime.utcnow() - timedelta(days=days)

    # Fetch all events and filter based on event_date (fallback to created_at)
    events = session.query(Event).all()

    open_count = 0
    in_progress_count = 0
    resolved_count = 0

    for e in events:
        date_to_use = e.event_date if e.event_date else e.created_at
        if date_to_use >= thirty_days_ago:
            if e.status == EventStatus.OPEN:
                open_count += 1
            elif e.status == EventStatus.IN_PROGRESS:
                in_progress_count += 1
            elif e.status == EventStatus.RESOLVED:
                resolved_count += 1

    return {
        "labels": ["Open", "In Progress", "Resolved"],
        "data": [open_count, in_progress_count, resolved_count]
    }


# Events CRUD
@app.get("/events", response_class=HTMLResponse)
async def list_events(request: Request):
    session = get_session(DEFAULT_DB_PATH)
    events = (
        session.query(Event)
        .order_by(
            Event.event_date.is_(None),
            Event.event_date.desc(),
            Event.created_at.desc(),
        )
        .all()
    )
    template = env.get_template("events/list.html")
    return template.render(request=request, events=events)


@app.get("/events/{id}", response_class=HTMLResponse)
async def view_event(request: Request, id: int):
    session = get_session(DEFAULT_DB_PATH)
    event = session.query(Event).filter(Event.id == id).first()
    if not event:
        return "Not found", 404
    template = env.get_template("events/detail.html")
    return template.render(request=request, event=event)


@app.get("/events/new/form", response_class=HTMLResponse)
async def new_event_form(request: Request):
    session = get_session(DEFAULT_DB_PATH)
    apts = session.query(APT).order_by(APT.name).all()
    template = env.get_template("events/form.html")
    result = template.render(request=request, event=None, action="/events/new", apts=apts)
    session.close()
    return result


@app.post("/events/new")
async def create_event(
    title: str = Form(...),
    description: Optional[str] = Form(None),
    severity: Optional[str] = Form(None),
    type: Optional[str] = Form(None),
    status: str = Form("open"),
    event_date: Optional[str] = Form(None),
    closed_date: Optional[str] = Form(None),
    apt_ids: list = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    parsed_date = None
    if event_date:
        try:
            parsed_date = datetime.strptime(event_date, '%Y-%m-%d')
        except ValueError:
            pass
    parsed_closed = None
    if closed_date:
        try:
            parsed_closed = datetime.strptime(closed_date, '%Y-%m-%d')
        except ValueError:
            pass
    event = Event(
        title=title,
        description=description,
        severity=severity,
        type=(EventType[type.upper()] if type else None),
        status=EventStatus[status.upper()],
        event_date=parsed_date,
        closed_date=parsed_closed,
    )
    
    # Link APTs if provided
    if apt_ids:
        if not isinstance(apt_ids, list):
            apt_ids = [apt_ids]
        for apt_id in apt_ids:
            try:
                apt = session.query(APT).filter(APT.id == int(apt_id)).first()
                if apt and apt not in event.apts:
                    event.apts.append(apt)
            except (ValueError, TypeError):
                pass
    
    session.add(event)
    session.commit()
    event_id = event.id
    session.close()
    return RedirectResponse(url=f"/events/{event_id}", status_code=303)


@app.get("/events/{id}/edit", response_class=HTMLResponse)
async def edit_event_form(request: Request, id: int):
    session = get_session(DEFAULT_DB_PATH)
    event = session.query(Event).filter(Event.id == id).first()
    if not event:
        session.close()
        return "Not found", 404
    apts = session.query(APT).order_by(APT.name).all()
    template = env.get_template("events/form.html")
    result = template.render(request=request, event=event, action=f"/events/{id}/edit", apts=apts)
    session.close()
    return result


@app.post("/events/{id}/edit")
async def update_event(
    id: int,
    title: str = Form(...),
    description: Optional[str] = Form(None),
    severity: Optional[str] = Form(None),
    type: Optional[str] = Form(None),
    status: str = Form(...),
    event_date: Optional[str] = Form(None),
    closed_date: Optional[str] = Form(None),
    apt_ids: list = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    event = session.query(Event).filter(Event.id == id).first()
    if event:
        parsed_date = None
        if event_date:
            try:
                parsed_date = datetime.strptime(event_date, '%Y-%m-%d')
            except ValueError:
                pass
        parsed_closed = None
        if closed_date:
            try:
                parsed_closed = datetime.strptime(closed_date, '%Y-%m-%d')
            except ValueError:
                pass
        event.title = title
        event.description = description
        event.severity = severity
        event.type = (EventType[type.upper()] if type else None)
        event.status = EventStatus[status.upper()]
        event.event_date = parsed_date
        event.closed_date = parsed_closed
        
        # Update APT associations
        event.apts.clear()
        if apt_ids:
            if not isinstance(apt_ids, list):
                apt_ids = [apt_ids]
            for apt_id in apt_ids:
                try:
                    apt = session.query(APT).filter(APT.id == int(apt_id)).first()
                    if apt and apt not in event.apts:
                        event.apts.append(apt)
                except (ValueError, TypeError):
                    pass
        
        session.commit()
    session.close()
    return RedirectResponse(url=f"/events/{id}", status_code=303)


@app.post("/events/{id}/delete")
async def delete_event(id: int):
    session = get_session(DEFAULT_DB_PATH)
    event = session.query(Event).filter(Event.id == id).first()
    if event:
        session.delete(event)
        session.commit()
    return RedirectResponse(url="/events", status_code=303)


# Malware CRUD (linked to events)
@app.get("/events/{event_id}/malware/new/form", response_class=HTMLResponse)
async def new_malware_form(request: Request, event_id: int):
    session = get_session(DEFAULT_DB_PATH)
    event = session.query(Event).filter(Event.id == event_id).first()
    if not event:
        session.close()
        return "Event not found", 404
    families = session.query(MalwareFamily).order_by(MalwareFamily.name.asc()).all()
    apts = session.query(APT).order_by(APT.name).all()
    template = env.get_template("malware/form.html")
    result = template.render(
        request=request,
        malware=None,
        event=event,
        families=families,
        apts=apts,
        action=f"/events/{event_id}/malware/new",
    )
    session.close()
    return result


@app.post("/events/{event_id}/malware/new")
async def create_malware(
    event_id: int,
    name: str = Form(...),
    family: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
    apt_ids: list = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    parsed_date = None
    if occurrence_date:
        try:
            parsed_date = datetime.strptime(occurrence_date, '%Y-%m-%d')
        except ValueError:
            pass
    family_ref = get_or_create_family(session, family)
    malware = Malware(
        name=name,
        family=family_ref.name if family_ref else None,
        family_id=family_ref.id if family_ref else None,
        description=description,
        occurrence_date=parsed_date,
        event_id=event_id,
    )
    
    # Link APTs if provided
    if apt_ids:
        if not isinstance(apt_ids, list):
            apt_ids = [apt_ids]
        for apt_id in apt_ids:
            try:
                apt = session.query(APT).filter(APT.id == int(apt_id)).first()
                if apt and apt not in malware.apts:
                    malware.apts.append(apt)
            except (ValueError, TypeError):
                pass
    
    session.add(malware)
    session.commit()
    session.close()
    return RedirectResponse(url=f"/events/{event_id}", status_code=303)


@app.get("/malware/{id}/edit", response_class=HTMLResponse)
async def edit_malware_form(request: Request, id: int):
    session = get_session(DEFAULT_DB_PATH)
    malware = session.query(Malware).filter(Malware.id == id).first()
    if not malware:
        session.close()
        return "Not found", 404
    families = session.query(MalwareFamily).order_by(MalwareFamily.name.asc()).all()
    apts = session.query(APT).order_by(APT.name).all()
    template = env.get_template("malware/form.html")
    result = template.render(
        request=request,
        malware=malware,
        event=malware.event,
        families=families,
        apts=apts,
        action=f"/malware/{id}/edit",
    )
    session.close()
    return result


@app.post("/malware/{id}/edit")
async def update_malware(
    id: int,
    name: str = Form(...),
    family: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
    apt_ids: list = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    malware = session.query(Malware).filter(Malware.id == id).first()
    if malware:
        redirect_event_id = malware.event_id
        parsed_date = None
        if occurrence_date:
            try:
                parsed_date = datetime.strptime(occurrence_date, '%Y-%m-%d')
            except ValueError:
                pass
        family_ref = get_or_create_family(session, family)
        malware.name = name
        malware.family = family_ref.name if family_ref else None
        malware.family_id = family_ref.id if family_ref else None
        malware.description = description
        malware.occurrence_date = parsed_date
        
        # Update APT associations
        malware.apts.clear()
        if apt_ids:
            if not isinstance(apt_ids, list):
                apt_ids = [apt_ids]
            for apt_id in apt_ids:
                try:
                    apt = session.query(APT).filter(APT.id == int(apt_id)).first()
                    if apt and apt not in malware.apts:
                        malware.apts.append(apt)
                except (ValueError, TypeError):
                    pass
        
        session.commit()
        session.close()
        return RedirectResponse(url=f"/events/{redirect_event_id}", status_code=303)
    session.close()
    return RedirectResponse(url="/events", status_code=303)


@app.post("/malware/{id}/delete")
async def delete_malware(id: int):
    session = get_session(DEFAULT_DB_PATH)
    malware = session.query(Malware).filter(Malware.id == id).first()
    if malware:
        event_id = malware.event_id
        session.delete(malware)
        session.commit()
        return RedirectResponse(url=f"/events/{event_id}", status_code=303)
    return RedirectResponse(url="/events", status_code=303)


# Phishing CRUD (linked to events)
@app.get("/events/{event_id}/phish/new/form", response_class=HTMLResponse)
async def new_phish_form(request: Request, event_id: int):
    session = get_session(DEFAULT_DB_PATH)
    event = session.query(Event).filter(Event.id == event_id).first()
    if not event:
        session.close()
        return "Event not found", 404
    apts = session.query(APT).order_by(APT.name).all()
    template = env.get_template("phish/form.html")
    result = template.render(request=request, phish=None, event=event, apts=apts, action=f"/events/{event_id}/phish/new")
    session.close()
    return result


@app.post("/events/{event_id}/phish/new")
async def create_phish(
    event_id: int,
    subject: Optional[str] = Form(None),
    sender: Optional[str] = Form(None),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    risk_level: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
    apt_ids: Optional[List[int]] = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    parsed_date = None
    if occurrence_date:
        try:
            parsed_date = datetime.strptime(occurrence_date, '%Y-%m-%d')
        except ValueError:
            pass
    phish = Phish(
        subject=subject,
        sender=sender,
        target=target,
        description=description,
        risk_level=risk_level,
        occurrence_date=parsed_date,
        event_id=event_id,
    )
    
    # Link APTs if provided
    if apt_ids:
        if not isinstance(apt_ids, list):
            apt_ids = [apt_ids]
        for apt_id in apt_ids:
            try:
                apt = session.query(APT).filter(APT.id == int(apt_id)).first()
                if apt and apt not in phish.apts:
                    phish.apts.append(apt)
            except (ValueError, TypeError):
                pass
    
    session.add(phish)
    session.commit()
    session.close()
    return RedirectResponse(url=f"/events/{event_id}", status_code=303)


@app.get("/phish/{id}/edit", response_class=HTMLResponse)
async def edit_phish_form(request: Request, id: int):
    session = get_session(DEFAULT_DB_PATH)
    phish = session.query(Phish).filter(Phish.id == id).first()
    if not phish:
        session.close()
        return "Not found", 404
    apts = session.query(APT).order_by(APT.name).all()
    template = env.get_template("phish/form.html")
    result = template.render(request=request, phish=phish, event=phish.event, apts=apts, action=f"/phish/{id}/edit")
    session.close()
    return result


@app.post("/phish/{id}/edit")
async def update_phish(
    id: int,
    subject: Optional[str] = Form(None),
    sender: Optional[str] = Form(None),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    risk_level: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
    apt_ids: Optional[List[int]] = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    phish = session.query(Phish).filter(Phish.id == id).first()
    if phish:
        redirect_event_id = phish.event_id
        parsed_date = None
        if occurrence_date:
            try:
                parsed_date = datetime.strptime(occurrence_date, '%Y-%m-%d')
            except ValueError:
                pass
        phish.subject = subject
        phish.sender = sender
        phish.target = target
        phish.description = description
        phish.risk_level = risk_level
        phish.occurrence_date = parsed_date
        
        # Update APT associations
        phish.apts.clear()
        if apt_ids:
            if not isinstance(apt_ids, list):
                apt_ids = [apt_ids]
            for apt_id in apt_ids:
                try:
                    apt = session.query(APT).filter(APT.id == int(apt_id)).first()
                    if apt and apt not in phish.apts:
                        phish.apts.append(apt)
                except (ValueError, TypeError):
                    pass
        
        session.commit()
        session.close()
        if redirect_event_id:
            return RedirectResponse(url=f"/events/{redirect_event_id}", status_code=303)
        else:
            return RedirectResponse(url="/phishing", status_code=303)
    session.close()
    return RedirectResponse(url="/phishing", status_code=303)


@app.post("/phish/{id}/delete")
async def delete_phish(id: int):
    session = get_session(DEFAULT_DB_PATH)
    phish = session.query(Phish).filter(Phish.id == id).first()
    if phish:
        event_id = phish.event_id
        session.delete(phish)
        session.commit()
        return RedirectResponse(url=f"/events/{event_id}", status_code=303)
    return RedirectResponse(url="/events", status_code=303)


# IOC CRUD (linked to malware or phishing)
@app.get("/malware/{malware_id}/ioc/new/form", response_class=HTMLResponse)
async def new_malware_ioc_form(request: Request, malware_id: int):
    session = get_session(DEFAULT_DB_PATH)
    malware = session.query(Malware).filter(Malware.id == malware_id).first()
    if not malware:
        return "Malware not found", 404
    template = env.get_template("ioc/form.html")
    return template.render(request=request, ioc=None, parent_type="malware", parent_id=malware_id, action=f"/malware/{malware_id}/ioc/new")


@app.post("/malware/{malware_id}/ioc/new")
async def create_malware_ioc(
    malware_id: int,
    type: str = Form(...),
    value: str = Form(...),
    description: Optional[str] = Form(None),
    confidence: Optional[int] = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    malware = session.query(Malware).filter(Malware.id == malware_id).first()
    if malware:
        ioc = IOC(
            type=type,
            value=value,
            description=description,
            confidence=confidence,
            malware_id=malware_id,
        )
        session.add(ioc)
        session.commit()
        if malware.event_id:
            return RedirectResponse(url=f"/events/{malware.event_id}", status_code=303)
        else:
            return RedirectResponse(url=f"/malware/{malware_id}", status_code=303)
    return RedirectResponse(url="/malware", status_code=303)


@app.get("/phish/{phish_id}/ioc/new/form", response_class=HTMLResponse)
async def new_phish_ioc_form(request: Request, phish_id: int):
    session = get_session(DEFAULT_DB_PATH)
    phish = session.query(Phish).filter(Phish.id == phish_id).first()
    if not phish:
        return "Phishing not found", 404
    template = env.get_template("ioc/form.html")
    return template.render(request=request, ioc=None, parent_type="phish", parent_id=phish_id, action=f"/phish/{phish_id}/ioc/new")


@app.post("/phish/{phish_id}/ioc/new")
async def create_phish_ioc(
    phish_id: int,
    type: str = Form(...),
    value: str = Form(...),
    description: Optional[str] = Form(None),
    confidence: Optional[int] = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    phish = session.query(Phish).filter(Phish.id == phish_id).first()
    if phish:
        ioc = IOC(
            type=type,
            value=value,
            description=description,
            confidence=confidence,
            phish_id=phish_id,
        )
        session.add(ioc)
        session.commit()
        if phish.event_id:
            return RedirectResponse(url=f"/events/{phish.event_id}", status_code=303)
        else:
            return RedirectResponse(url=f"/phishing/{phish_id}", status_code=303)
    return RedirectResponse(url="/phishing", status_code=303)


@app.post("/ioc/{id}/delete")
async def delete_ioc(id: int):
    session = get_session(DEFAULT_DB_PATH)
    ioc = session.query(IOC).filter(IOC.id == id).first()
    if ioc:
        if ioc.malware_id:
            malware = session.query(Malware).filter(Malware.id == ioc.malware_id).first()
            event_id = malware.event_id if malware else None
        elif ioc.phish_id:
            phish = session.query(Phish).filter(Phish.id == ioc.phish_id).first()
            event_id = phish.event_id if phish else None
        else:
            event_id = None
        session.delete(ioc)
        session.commit()
        if event_id:
            return RedirectResponse(url=f"/events/{event_id}", status_code=303)
    return RedirectResponse(url="/events", status_code=303)


# Mitigation CRUD (linked to events)
@app.get("/events/{event_id}/mitigation/new/form", response_class=HTMLResponse)
async def new_mitigation_form(request: Request, event_id: int):
    session = get_session(DEFAULT_DB_PATH)
    event = session.query(Event).filter(Event.id == event_id).first()
    if not event:
        session.close()
        return "Event not found", 404
    apts = session.query(APT).order_by(APT.name).all()
    template = env.get_template("mitigation/form.html")
    result = template.render(request=request, mitigation=None, event=event, apts=apts, action=f"/events/{event_id}/mitigation/new")
    session.close()
    return result


@app.post("/events/{event_id}/mitigation/new")
async def create_mitigation(
    event_id: int,
    title: str = Form(...),
    description: Optional[str] = Form(None),
    assigned_to: Optional[str] = Form(None),
    apt_ids: list = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    mitigation = Mitigation(
        title=title,
        description=description,
        assigned_to=assigned_to,
        event_id=event_id,
    )
    
    # Note: For mitigations, APTs are linked through the parent event
    # The apt_ids field here is mainly for reference; actual linking is to the event
    # We could optionally add direct APT linking to Mitigation in the future
    
    session.add(mitigation)
    session.commit()
    session.close()
    return RedirectResponse(url=f"/events/{event_id}", status_code=303)


@app.get("/mitigation/{id}/edit", response_class=HTMLResponse)
async def edit_mitigation_form(request: Request, id: int):
    session = get_session(DEFAULT_DB_PATH)
    mitigation = session.query(Mitigation).filter(Mitigation.id == id).first()
    if not mitigation:
        session.close()
        return "Not found", 404
    apts = session.query(APT).order_by(APT.name).all()
    template = env.get_template("mitigation/form.html")
    result = template.render(request=request, mitigation=mitigation, event=mitigation.event, apts=apts, action=f"/mitigation/{id}/edit")
    session.close()
    return result


@app.post("/mitigation/{id}/edit")
async def update_mitigation(
    id: int,
    title: str = Form(...),
    description: Optional[str] = Form(None),
    assigned_to: Optional[str] = Form(None),
    apt_ids: list = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    mitigation = session.query(Mitigation).filter(Mitigation.id == id).first()
    if mitigation:
        redirect_event_id = mitigation.event_id
        mitigation.title = title
        mitigation.description = description
        mitigation.assigned_to = assigned_to
        session.commit()
        session.close()
        return RedirectResponse(url=f"/events/{redirect_event_id}", status_code=303)
    session.close()
    return RedirectResponse(url="/events", status_code=303)


@app.post("/mitigation/{id}/delete")
async def delete_mitigation(id: int):
    session = get_session(DEFAULT_DB_PATH)
    mitigation = session.query(Mitigation).filter(Mitigation.id == id).first()
    if mitigation:
        event_id = mitigation.event_id
        session.delete(mitigation)
        session.commit()
        return RedirectResponse(url=f"/events/{event_id}", status_code=303)
    return RedirectResponse(url="/events", status_code=303)


# Standalone entity management pages
@app.get("/malware", response_class=HTMLResponse)
async def list_all_malware(request: Request):
    session = get_session(DEFAULT_DB_PATH)
    malware_list = (
        session.query(Malware)
        .order_by(
            Malware.occurrence_date.is_(None),
            Malware.occurrence_date.desc(),
            Malware.created_at.desc(),
        )
        .all()
    )
    template = env.get_template("malware/list.html")
    return template.render(request=request, malware_list=malware_list)


@app.get("/malware/{id}", response_class=HTMLResponse)
async def view_malware(request: Request, id: int):
    session = get_session(DEFAULT_DB_PATH)
    malware = session.query(Malware).filter(Malware.id == id).first()
    if not malware:
        return "Not found", 404
    template = env.get_template("malware/detail.html")
    return template.render(request=request, malware=malware)


@app.get("/malware/new/form", response_class=HTMLResponse)
async def new_standalone_malware_form(request: Request):
    session = get_session(DEFAULT_DB_PATH)
    events = (
        session.query(Event)
        .order_by(
            Event.event_date.is_(None),
            Event.event_date.desc(),
            Event.created_at.desc(),
        )
        .all()
    )
    families = session.query(MalwareFamily).order_by(MalwareFamily.name.asc()).all()
    apts = session.query(APT).order_by(APT.name).all()
    template = env.get_template("malware/standalone_form.html")
    result = template.render(
        request=request,
        malware=None,
        events=events,
        families=families,
        apts=apts,
        action="/malware/new",
    )
    session.close()
    return result


@app.post("/malware/new")
async def create_standalone_malware(
    name: str = Form(...),
    family: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
    event_id: Optional[int] = Form(None),
    apt_ids: list = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    parsed_date = None
    if occurrence_date:
        try:
            parsed_date = datetime.strptime(occurrence_date, '%Y-%m-%d')
        except ValueError:
            pass
    family_ref = get_or_create_family(session, family)
    malware = Malware(
        name=name,
        family=family_ref.name if family_ref else None,
        family_id=family_ref.id if family_ref else None,
        description=description,
        occurrence_date=parsed_date,
        event_id=event_id if event_id else None,
    )
    
    # Link APTs if provided
    if apt_ids:
        if not isinstance(apt_ids, list):
            apt_ids = [apt_ids]
        for apt_id in apt_ids:
            try:
                apt = session.query(APT).filter(APT.id == int(apt_id)).first()
                if apt and apt not in malware.apts:
                    malware.apts.append(apt)
            except (ValueError, TypeError):
                pass
    
    session.add(malware)
    session.commit()
    session.close()
    return RedirectResponse(url="/malware", status_code=303)


@app.get("/phishing", response_class=HTMLResponse)
async def list_all_phishing(request: Request):
    session = get_session(DEFAULT_DB_PATH)
    phishing_list = (
        session.query(Phish)
        .order_by(
            Phish.occurrence_date.is_(None),
            Phish.occurrence_date.desc(),
            Phish.created_at.desc(),
        )
        .all()
    )
    template = env.get_template("phish/list.html")
    return template.render(request=request, phishing_list=phishing_list)


@app.get("/phishing/{id}", response_class=HTMLResponse)
async def view_phishing(request: Request, id: int):
    session = get_session(DEFAULT_DB_PATH)
    phish = session.query(Phish).filter(Phish.id == id).first()
    if not phish:
        return "Not found", 404
    template = env.get_template("phish/detail.html")
    return template.render(request=request, phish=phish)


@app.get("/phishing/new/form", response_class=HTMLResponse)
async def new_standalone_phish_form(request: Request):
    session = get_session(DEFAULT_DB_PATH)
    events = (
        session.query(Event)
        .order_by(
            Event.event_date.is_(None),
            Event.event_date.desc(),
            Event.created_at.desc(),
        )
        .all()
    )
    apts = session.query(APT).order_by(APT.name).all()
    template = env.get_template("phish/standalone_form.html")
    result = template.render(request=request, phish=None, events=events, apts=apts, action="/phishing/new")
    session.close()
    return result


@app.post("/phishing/new")
async def create_standalone_phish(
    subject: Optional[str] = Form(None),
    sender: Optional[str] = Form(None),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    risk_level: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
    event_id: Optional[int] = Form(None),
    apt_ids: list = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    parsed_date = None
    if occurrence_date:
        try:
            parsed_date = datetime.strptime(occurrence_date, '%Y-%m-%d')
        except ValueError:
            pass
    phish = Phish(
        subject=subject,
        sender=sender,
        target=target,
        description=description,
        risk_level=risk_level,
        occurrence_date=parsed_date,
        event_id=event_id if event_id else None,
    )
    
    # Link APTs if provided
    if apt_ids:
        if not isinstance(apt_ids, list):
            apt_ids = [apt_ids]
        for apt_id in apt_ids:
            try:
                apt = session.query(APT).filter(APT.id == int(apt_id)).first()
                if apt and apt not in phish.apts:
                    phish.apts.append(apt)
            except (ValueError, TypeError):
                pass
    
    session.add(phish)
    session.commit()
    session.close()
    return RedirectResponse(url="/phishing", status_code=303)


@app.get("/iocs", response_class=HTMLResponse)
async def list_all_iocs(request: Request):
    session = get_session(DEFAULT_DB_PATH)
    iocs = session.query(IOC).order_by(IOC.created_at.desc()).all()
    template = env.get_template("ioc/list.html")
    return template.render(request=request, iocs=iocs)


@app.get("/iocs/new/form", response_class=HTMLResponse)
async def new_standalone_ioc_form(request: Request):
    session = get_session(DEFAULT_DB_PATH)
    malware_list = session.query(Malware).order_by(Malware.created_at.desc()).all()
    phishing_list = session.query(Phish).order_by(Phish.created_at.desc()).all()
    template = env.get_template("ioc/standalone_form.html")
    return template.render(request=request, ioc=None, malware_list=malware_list, phishing_list=phishing_list, action="/iocs/new")


@app.post("/iocs/new")
async def create_standalone_ioc(
    type: str = Form(...),
    value: str = Form(...),
    description: Optional[str] = Form(None),
    confidence: Optional[int] = Form(None),
    link_type: Optional[str] = Form(None),
    link_id: Optional[int] = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    ioc = IOC(
        type=type,
        value=value,
        description=description,
        confidence=confidence,
        malware_id=link_id if link_type == "malware" else None,
        phish_id=link_id if link_type == "phishing" else None,
    )
    session.add(ioc)
    session.commit()
    return RedirectResponse(url="/iocs", status_code=303)


@app.get("/mitigations", response_class=HTMLResponse)
async def list_all_mitigations(request: Request):
    session = get_session(DEFAULT_DB_PATH)
    mitigations = session.query(Mitigation).order_by(Mitigation.created_at.desc()).all()
    template = env.get_template("mitigation/list.html")
    return template.render(request=request, mitigations=mitigations)


@app.get("/mitigations/new/form", response_class=HTMLResponse)
async def new_standalone_mitigation_form(request: Request):
    session = get_session(DEFAULT_DB_PATH)
    events = (
        session.query(Event)
        .order_by(
            Event.event_date.is_(None),
            Event.event_date.desc(),
            Event.created_at.desc(),
        )
        .all()
    )
    template = env.get_template("mitigation/standalone_form.html")
    return template.render(request=request, mitigation=None, events=events, action="/mitigations/new")


@app.post("/mitigations/new")
async def create_standalone_mitigation(
    title: str = Form(...),
    description: Optional[str] = Form(None),
    assigned_to: Optional[str] = Form(None),
    event_id: int = Form(...),
):
    session = get_session(DEFAULT_DB_PATH)
    mitigation = Mitigation(
        title=title,
        description=description,
        assigned_to=assigned_to,
        event_id=event_id,
    )
    session.add(mitigation)
    session.commit()
    return RedirectResponse(url="/mitigations", status_code=303)


# Settings
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Display settings page with database statistics and management options"""
    import os
    session = get_session(DEFAULT_DB_PATH)
    
    # Get database statistics
    stats = {
        "events": session.query(func.count(Event.id)).scalar() or 0,
        "malware": session.query(func.count(Malware.id)).scalar() or 0,
        "phishing": session.query(func.count(Phish.id)).scalar() or 0,
        "iocs": session.query(func.count(IOC.id)).scalar() or 0,
        "mitigations": session.query(func.count(Mitigation.id)).scalar() or 0,
    }
    
    # Get database file info
    db_path = DEFAULT_DB_PATH
    db_info = {
        "path": str(db_path),
        "exists": db_path.exists(),
        "size": round(db_path.stat().st_size / 1024 / 1024, 2) if db_path.exists() else 0,  # MB
    }

    families = session.query(MalwareFamily).order_by(MalwareFamily.name.asc()).all()
    security_email = load_security_email()
    
    template = env.get_template("settings.html")
    return template.render(request=request, stats=stats, db_info=db_info, families=families, security_email=security_email)


@app.post("/settings/clear-data")
async def clear_all_data():
    """Clear all data from the database (keeps schema)"""
    session = get_session(DEFAULT_DB_PATH)
    
    # Delete all records
    session.query(IOC).delete()
    session.query(Mitigation).delete()
    session.query(Malware).delete()
    session.query(Phish).delete()
    session.query(Event).delete()
    
    session.commit()
    return RedirectResponse(url="/settings?cleared=true", status_code=303)


@app.post("/settings/security-email")
async def update_security_email(security_email: str = Form(...)):
    """Update security contact email for reports."""
    email = security_email.strip() or DEFAULT_SECURITY_EMAIL
    save_security_email(email)
    return RedirectResponse(url="/settings?security_email_updated=true", status_code=303)


@app.post("/settings/malware-family")
async def add_malware_family(name: str = Form(...)):
    """Add a new malware family to the reference table."""
    session = get_session(DEFAULT_DB_PATH)
    fam = get_or_create_family(session, name)
    session.commit()
    return RedirectResponse(
        url=f"/settings?family_added={fam.id if fam else ''}", status_code=303
    )


@app.get("/settings/backup")
async def backup_database():
    """Create a backup of the database"""
    import shutil
    from fastapi.responses import FileResponse
    
    backup_name = f"titan_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sqlite"
    backup_path = DEFAULT_DB_PATH.parent / backup_name
    
    # Copy database file
    shutil.copy2(DEFAULT_DB_PATH, backup_path)
    
    return FileResponse(
        path=backup_path,
        filename=backup_name,
        media_type="application/x-sqlite3"
    )


@app.get("/settings/export")
async def export_data():
    """Export all data as JSON"""
    from fastapi.responses import JSONResponse
    
    session = get_session(DEFAULT_DB_PATH)
    
    # Get all data
    events = session.query(Event).all()
    malware = session.query(Malware).all()
    phishing = session.query(Phish).all()
    iocs = session.query(IOC).all()
    mitigations = session.query(Mitigation).all()
    
    export_data = {
        "export_date": datetime.now().isoformat(),
        "events": [
            {
                "id": e.id,
                "title": e.title,
                "description": e.description,
                "severity": e.severity,
                "status": e.status.value,
                "event_date": e.event_date.isoformat() if e.event_date else None,
                "detected_date": e.detected_date.isoformat(),
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
        "malware": [
            {
                "id": m.id,
                "name": m.name,
                "family": m.family,
                "family_id": m.family_id,
                "description": m.description,
                "occurrence_date": m.occurrence_date.isoformat() if m.occurrence_date else None,
                "event_id": m.event_id,
                "created_at": m.created_at.isoformat(),
            }
            for m in malware
        ],
        "phishing": [
            {
                "id": p.id,
                "subject": p.subject,
                "sender": p.sender,
                "target": p.target,
                "description": p.description,
                "occurrence_date": p.occurrence_date.isoformat() if p.occurrence_date else None,
                "event_id": p.event_id,
                "created_at": p.created_at.isoformat(),
            }
            for p in phishing
        ],
        "iocs": [
            {
                "id": i.id,
                "type": i.type,
                "value": i.value,
                "description": i.description,
                "confidence": i.confidence,
                "malware_id": i.malware_id,
                "phish_id": i.phish_id,
                "created_at": i.created_at.isoformat(),
            }
            for i in iocs
        ],
        "mitigations": [
            {
                "id": m.id,
                "title": m.title,
                "description": m.description,
                "assigned_to": m.assigned_to,
                "event_id": m.event_id,
                "created_at": m.created_at.isoformat(),
                "updated_at": m.updated_at.isoformat(),
            }
            for m in mitigations
        ],
    }
    
    return JSONResponse(
        content=export_data,
        headers={
            "Content-Disposition": f"attachment; filename=titan_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        }
    )


@app.post("/settings/import/malware-csv")
async def import_malware_csv(file: UploadFile = File(...)):
    """Import malware records from a CSV file.

    Expected columns (header names, case-insensitive):
    - name (required)
    - family (optional)
    - description (optional)
    - occurrence_date (YYYY-MM-DD, optional)
    - event_id (optional, will link if exists)
    """
    session = get_session(DEFAULT_DB_PATH)
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    # Remove BOM at file start if present
    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")
    reader = csv.DictReader(io.StringIO(text))

    imported = 0
    failed = 0

    for row in reader:
        row = normalize_row(row)
        name = (row.get("name") or "").strip()
        if not name:
            failed += 1
            continue

        family = (row.get("family") or "").strip() or None
        description = (row.get("description") or "").strip() or None
        occ = parse_date(row.get("occurrence_date") or row.get("date"))

        family_ref = get_or_create_family(session, family)

        event_id = None
        raw_eid = row.get("event_id") or row.get("event")
        if raw_eid:
            try:
                event_id = int(raw_eid)
            except ValueError:
                event_id = None

        malware = Malware(
            name=name,
            family=family_ref.name if family_ref else None,
            family_id=family_ref.id if family_ref else None,
            description=description,
            occurrence_date=occ,
            event_id=event_id,
        )
        session.add(malware)
        imported += 1

    session.commit()
    return RedirectResponse(
        url=f"/settings?malware_imported={imported}&malware_failed={failed}",
        status_code=303,
    )


@app.post("/settings/import/phish-csv")
async def import_phish_csv(file: UploadFile = File(...)):
    """Import phishing records from a CSV file.

    Expected columns (header names, case-insensitive):
    - subject (required)
    - sender (optional)
    - target (optional)
    - description (optional)
    - risk_level (optional: low|medium|high|critical)
    - occurrence_date (YYYY-MM-DD, optional)
    - event_id (optional, will link if exists)
    """
    session = get_session(DEFAULT_DB_PATH)
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")
    reader = csv.DictReader(io.StringIO(text))

    imported = 0
    failed = 0

    for row in reader:
        row = normalize_row(row)
        subject = (row.get("subject") or "").strip()
        if not subject:
            failed += 1
            continue

        sender = (row.get("sender") or "").strip() or None
        target = (row.get("target") or "").strip() or None
        description = (row.get("description") or "").strip() or None
        risk_level = (row.get("risk_level") or "").strip().lower() or None
        if risk_level and risk_level not in {"low", "medium", "high", "critical"}:
            risk_level = None
        occ = parse_date(row.get("occurrence_date") or row.get("date"))

        event_id = None
        raw_eid = row.get("event_id") or row.get("event")
        if raw_eid:
            try:
                event_id = int(raw_eid)
            except ValueError:
                event_id = None

        phish = Phish(
            subject=subject,
            sender=sender,
            target=target,
            description=description,
            risk_level=risk_level,
            occurrence_date=occ,
            event_id=event_id,
        )
        session.add(phish)
        imported += 1

    session.commit()
    return RedirectResponse(
        url=f"/settings?phish_imported={imported}&phish_failed={failed}",
        status_code=303,
    )

# ==================== APT ENDPOINTS ====================

@app.get("/apts", response_class=HTMLResponse)
async def list_apts():
    """List all APTs"""
    session = get_session(DEFAULT_DB_PATH)
    apts = session.query(APT).order_by(APT.name).all()
    template = env.get_template("apts/list.html")
    result = template.render(apts=apts)
    session.close()
    return result


@app.get("/apts/{id}", response_class=HTMLResponse)
async def view_apt(id: int):
    """View APT details"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == id).first()
    if not apt:
        session.close()
        return "APT not found", 404
    template = env.get_template("apts/detail.html")
    result = template.render(apt=apt)
    session.close()
    return result


@app.get("/apts/new/form", response_class=HTMLResponse)
async def new_apt_form():
    """Show form to create new APT"""
    template = env.get_template("apts/new.html")
    return template.render()


@app.post("/apts/new")
async def create_apt(
    name: str = Form(...),
    aliases: str = Form(default=""),
    description: str = Form(default=""),
    country_origin: str = Form(default=""),
    primary_targets: str = Form(default=""),
    tactics: str = Form(default=""),
    techniques: str = Form(default=""),
    first_seen: str = Form(default=""),
    last_seen: str = Form(default=""),
):
    """Create new APT"""
    session = get_session(DEFAULT_DB_PATH)
    
    # Parse dates
    first_seen_dt = None
    last_seen_dt = None
    if first_seen:
        try:
            first_seen_dt = datetime.strptime(first_seen, '%Y-%m-%d')
        except ValueError:
            pass
    if last_seen:
        try:
            last_seen_dt = datetime.strptime(last_seen, '%Y-%m-%d')
        except ValueError:
            pass
    
    apt = APT(
        name=name.strip(),
        aliases=aliases.strip() or None,
        description=description.strip() or None,
        country_origin=country_origin.strip() or None,
        primary_targets=primary_targets.strip() or None,
        tactics=tactics.strip() or None,
        techniques=techniques.strip() or None,
        first_seen=first_seen_dt,
        last_seen=last_seen_dt,
    )
    session.add(apt)
    session.commit()
    apt_id = apt.id
    session.close()
    
    return RedirectResponse(url=f"/apts/{apt_id}", status_code=303)


@app.get("/apts/{id}/edit", response_class=HTMLResponse)
async def edit_apt_form(id: int):
    """Show form to edit APT"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == id).first()
    if not apt:
        session.close()
        return "APT not found", 404
    template = env.get_template("apts/edit.html")
    result = template.render(apt=apt)
    session.close()
    return result


@app.post("/apts/{id}/edit")
async def edit_apt(
    id: int,
    name: str = Form(...),
    aliases: str = Form(default=""),
    description: str = Form(default=""),
    country_origin: str = Form(default=""),
    primary_targets: str = Form(default=""),
    tactics: str = Form(default=""),
    techniques: str = Form(default=""),
    first_seen: str = Form(default=""),
    last_seen: str = Form(default=""),
):
    """Update APT details"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == id).first()
    if not apt:
        return "APT not found", 404
    
    # Parse dates
    first_seen_dt = None
    last_seen_dt = None
    if first_seen:
        try:
            first_seen_dt = datetime.strptime(first_seen, '%Y-%m-%d')
        except ValueError:
            pass
    if last_seen:
        try:
            last_seen_dt = datetime.strptime(last_seen, '%Y-%m-%d')
        except ValueError:
            pass
    
    apt.name = name.strip()
    apt.aliases = aliases.strip() or None
    apt.description = description.strip() or None
    apt.country_origin = country_origin.strip() or None
    apt.primary_targets = primary_targets.strip() or None
    apt.tactics = tactics.strip() or None
    apt.techniques = techniques.strip() or None
    apt.first_seen = first_seen_dt
    apt.last_seen = last_seen_dt
    
    session.commit()
    session.close()
    
    return RedirectResponse(url=f"/apts/{id}", status_code=303)


@app.post("/apts/{id}/delete")
async def delete_apt(id: int):
    """Delete APT"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == id).first()
    if apt:
        session.delete(apt)
        session.commit()
    session.close()
    return RedirectResponse(url="/apts", status_code=303)


# ==================== APT LINKING ENDPOINTS ====================

@app.post("/apts/{apt_id}/link/event/{event_id}")
async def link_apt_to_event(apt_id: int, event_id: int):
    """Link APT to an event"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == apt_id).first()
    event = session.query(Event).filter(Event.id == event_id).first()
    
    if apt and event and event not in apt.events:
        apt.events.append(event)
        session.commit()
    
    session.close()
    return RedirectResponse(url=f"/events/{event_id}", status_code=303)


@app.post("/apts/{apt_id}/unlink/event/{event_id}")
async def unlink_apt_from_event(apt_id: int, event_id: int):
    """Unlink APT from an event"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == apt_id).first()
    event = session.query(Event).filter(Event.id == event_id).first()
    
    if apt and event and event in apt.events:
        apt.events.remove(event)
        session.commit()
    
    session.close()
    return RedirectResponse(url=f"/events/{event_id}", status_code=303)


@app.post("/apts/{apt_id}/link/malware/{malware_id}")
async def link_apt_to_malware(apt_id: int, malware_id: int):
    """Link APT to malware"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == apt_id).first()
    malware = session.query(Malware).filter(Malware.id == malware_id).first()
    
    if apt and malware and malware not in apt.malware:
        apt.malware.append(malware)
        session.commit()
    
    session.close()
    return RedirectResponse(url=f"/malware/{malware_id}", status_code=303)


@app.post("/apts/{apt_id}/unlink/malware/{malware_id}")
async def unlink_apt_from_malware(apt_id: int, malware_id: int):
    """Unlink APT from malware"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == apt_id).first()
    malware = session.query(Malware).filter(Malware.id == malware_id).first()
    
    if apt and malware and malware in apt.malware:
        apt.malware.remove(malware)
        session.commit()
    
    session.close()
    return RedirectResponse(url=f"/malware/{malware_id}", status_code=303)


@app.post("/apts/{apt_id}/link/phish/{phish_id}")
async def link_apt_to_phish(apt_id: int, phish_id: int):
    """Link APT to phishing"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == apt_id).first()
    phish = session.query(Phish).filter(Phish.id == phish_id).first()
    
    if apt and phish and phish not in apt.phishing:
        apt.phishing.append(phish)
        session.commit()
    
    session.close()
    return RedirectResponse(url=f"/phish/{phish_id}", status_code=303)


@app.post("/apts/{apt_id}/unlink/phish/{phish_id}")
async def unlink_apt_from_phish(apt_id: int, phish_id: int):
    """Unlink APT from phishing"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == apt_id).first()
    phish = session.query(Phish).filter(Phish.id == phish_id).first()
    
    if apt and phish and phish in apt.phishing:
        apt.phishing.remove(phish)
        session.commit()
    
    session.close()
    return RedirectResponse(url=f"/phish/{phish_id}", status_code=303)


@app.post("/apts/{apt_id}/link/ioc/{ioc_id}")
async def link_apt_to_ioc(apt_id: int, ioc_id: int):
    """Link APT to IOC"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == apt_id).first()
    ioc = session.query(IOC).filter(IOC.id == ioc_id).first()
    
    if apt and ioc and ioc not in apt.iocs:
        apt.iocs.append(ioc)
        session.commit()
    
    session.close()
    return {"status": "success"}


@app.post("/apts/{apt_id}/unlink/ioc/{ioc_id}")
async def unlink_apt_from_ioc(apt_id: int, ioc_id: int):
    """Unlink APT from IOC"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == apt_id).first()
    ioc = session.query(IOC).filter(IOC.id == ioc_id).first()
    
    if apt and ioc and ioc in apt.iocs:
        apt.iocs.remove(ioc)
        session.commit()
    
    session.close()
    return {"status": "success"}


# ==================== APT API ENDPOINTS ====================

@app.get("/api/apts")
async def get_apts_json():
    """Get all APTs as JSON"""
    session = get_session(DEFAULT_DB_PATH)
    apts = session.query(APT).order_by(APT.name).all()
    result = []
    for apt in apts:
        result.append({
            "id": apt.id,
            "name": apt.name,
            "aliases": apt.aliases,
            "description": apt.description,
            "country_origin": apt.country_origin,
            "primary_targets": apt.primary_targets,
            "tactics": apt.tactics,
            "techniques": apt.techniques,
            "first_seen": apt.first_seen.isoformat() if apt.first_seen else None,
            "last_seen": apt.last_seen.isoformat() if apt.last_seen else None,
            "events_count": len(apt.events),
            "malware_count": len(apt.malware),
            "phishing_count": len(apt.phishing),
            "iocs_count": len(apt.iocs),
        })
    session.close()
    return result


@app.get("/api/apts/{id}")
async def get_apt_json(id: int):
    """Get APT details as JSON"""
    session = get_session(DEFAULT_DB_PATH)
    apt = session.query(APT).filter(APT.id == id).first()
    
    if not apt:
        return {"error": "APT not found"}, 404
    
    result = {
        "id": apt.id,
        "name": apt.name,
        "aliases": apt.aliases,
        "description": apt.description,
        "country_origin": apt.country_origin,
        "primary_targets": apt.primary_targets,
        "tactics": apt.tactics,
        "techniques": apt.techniques,
        "first_seen": apt.first_seen.isoformat() if apt.first_seen else None,
        "last_seen": apt.last_seen.isoformat() if apt.last_seen else None,
        "events": [{"id": e.id, "title": e.title} for e in apt.events],
        "malware": [{"id": m.id, "name": m.name} for m in apt.malware],
        "phishing": [{"id": p.id, "subject": p.subject} for p in apt.phishing],
        "iocs": [{"id": i.id, "type": i.type, "value": i.value} for i in apt.iocs],
    }
    
    session.close()
    return result


@app.get("/api/charts/apts-top")
async def top_apts(days: int = 30, top: int = 10):
    """Get top APTs by activity count within window"""
    from datetime import timedelta
    session = get_session(DEFAULT_DB_PATH)
    now = datetime.utcnow()
    window_start = now - timedelta(days=days)
    window_end = now
    
    apts = session.query(APT).all()
    apt_counts = {}
    
    for apt in apts:
        # Count recent activity from linked events
        recent_events = [e for e in apt.events 
                        if window_start <= (e.created_at or e.detected_date) < window_end]
        recent_malware = [m for m in apt.malware 
                         if window_start <= (m.created_at) < window_end]
        recent_phishing = [p for p in apt.phishing 
                          if window_start <= (p.created_at) < window_end]
        
        count = len(recent_events) + len(recent_malware) + len(recent_phishing)
        if count > 0:
            apt_counts[apt.name] = count
    
    sorted_apts = sorted(apt_counts.items(), key=lambda x: x[1], reverse=True)[:top]
    labels = [name for name, _ in sorted_apts]
    data = [count for _, count in sorted_apts]
    
    session.close()
    return {"labels": labels, "data": data}