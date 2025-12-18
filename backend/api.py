from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import io
import csv
from sqlalchemy import func
from .db_init import get_session, DEFAULT_DB_PATH
from .db_models import Event, Malware, MalwareFamily, Phish, IOC, Mitigation, EventStatus, EventType
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime
from typing import Optional

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "frontend" / "templates"
STATIC_DIR = Path(__file__).resolve().parent.parent / "frontend" / "static"

env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)

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
    template = env.get_template("events/form.html")
    return template.render(request=request, event=None, action="/events/new")


@app.post("/events/new")
async def create_event(
    title: str = Form(...),
    description: Optional[str] = Form(None),
    severity: Optional[str] = Form(None),
    type: Optional[str] = Form(None),
    status: str = Form("open"),
    event_date: Optional[str] = Form(None),
    closed_date: Optional[str] = Form(None),
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
    session.add(event)
    session.commit()
    return RedirectResponse(url=f"/events/{event.id}", status_code=303)


@app.get("/events/{id}/edit", response_class=HTMLResponse)
async def edit_event_form(request: Request, id: int):
    session = get_session(DEFAULT_DB_PATH)
    event = session.query(Event).filter(Event.id == id).first()
    if not event:
        return "Not found", 404
    template = env.get_template("events/form.html")
    return template.render(request=request, event=event, action=f"/events/{id}/edit")


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
        session.commit()
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
        return "Event not found", 404
    families = session.query(MalwareFamily).order_by(MalwareFamily.name.asc()).all()
    template = env.get_template("malware/form.html")
    return template.render(
        request=request,
        malware=None,
        event=event,
        families=families,
        action=f"/events/{event_id}/malware/new",
    )


@app.post("/events/{event_id}/malware/new")
async def create_malware(
    event_id: int,
    name: str = Form(...),
    family: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
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
    session.add(malware)
    session.commit()
    return RedirectResponse(url=f"/events/{event_id}", status_code=303)


@app.get("/malware/{id}/edit", response_class=HTMLResponse)
async def edit_malware_form(request: Request, id: int):
    session = get_session(DEFAULT_DB_PATH)
    malware = session.query(Malware).filter(Malware.id == id).first()
    if not malware:
        return "Not found", 404
    families = session.query(MalwareFamily).order_by(MalwareFamily.name.asc()).all()
    template = env.get_template("malware/form.html")
    return template.render(
        request=request,
        malware=malware,
        event=malware.event,
        families=families,
        action=f"/malware/{id}/edit",
    )


@app.post("/malware/{id}/edit")
async def update_malware(
    id: int,
    name: str = Form(...),
    family: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    malware = session.query(Malware).filter(Malware.id == id).first()
    if malware:
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
        session.commit()
        return RedirectResponse(url=f"/events/{malware.event_id}", status_code=303)
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
        return "Event not found", 404
    template = env.get_template("phish/form.html")
    return template.render(request=request, phish=None, event=event, action=f"/events/{event_id}/phish/new")


@app.post("/events/{event_id}/phish/new")
async def create_phish(
    event_id: int,
    subject: Optional[str] = Form(None),
    sender: Optional[str] = Form(None),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
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
        occurrence_date=parsed_date,
        event_id=event_id,
    )
    session.add(phish)
    session.commit()
    return RedirectResponse(url=f"/events/{event_id}", status_code=303)


@app.get("/phish/{id}/edit", response_class=HTMLResponse)
async def edit_phish_form(request: Request, id: int):
    session = get_session(DEFAULT_DB_PATH)
    phish = session.query(Phish).filter(Phish.id == id).first()
    if not phish:
        return "Not found", 404
    template = env.get_template("phish/form.html")
    return template.render(request=request, phish=phish, event=phish.event, action=f"/phish/{id}/edit")


@app.post("/phish/{id}/edit")
async def update_phish(
    id: int,
    subject: Optional[str] = Form(None),
    sender: Optional[str] = Form(None),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    risk_level: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    phish = session.query(Phish).filter(Phish.id == id).first()
    if phish:
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
        session.commit()
        if phish.event_id:
            return RedirectResponse(url=f"/events/{phish.event_id}", status_code=303)
        else:
            return RedirectResponse(url="/phishing", status_code=303)
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
        return "Event not found", 404
    template = env.get_template("mitigation/form.html")
    return template.render(request=request, mitigation=None, event=event, action=f"/events/{event_id}/mitigation/new")


@app.post("/events/{event_id}/mitigation/new")
async def create_mitigation(
    event_id: int,
    title: str = Form(...),
    description: Optional[str] = Form(None),
    assigned_to: Optional[str] = Form(None),
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
    return RedirectResponse(url=f"/events/{event_id}", status_code=303)


@app.get("/mitigation/{id}/edit", response_class=HTMLResponse)
async def edit_mitigation_form(request: Request, id: int):
    session = get_session(DEFAULT_DB_PATH)
    mitigation = session.query(Mitigation).filter(Mitigation.id == id).first()
    if not mitigation:
        return "Not found", 404
    template = env.get_template("mitigation/form.html")
    return template.render(request=request, mitigation=mitigation, event=mitigation.event, action=f"/mitigation/{id}/edit")


@app.post("/mitigation/{id}/edit")
async def update_mitigation(
    id: int,
    title: str = Form(...),
    description: Optional[str] = Form(None),
    assigned_to: Optional[str] = Form(None),
):
    session = get_session(DEFAULT_DB_PATH)
    mitigation = session.query(Mitigation).filter(Mitigation.id == id).first()
    if mitigation:
        mitigation.title = title
        mitigation.description = description
        mitigation.assigned_to = assigned_to
        session.commit()
        return RedirectResponse(url=f"/events/{mitigation.event_id}", status_code=303)
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
    template = env.get_template("malware/standalone_form.html")
    return template.render(
        request=request,
        malware=None,
        events=events,
        families=families,
        action="/malware/new",
    )


@app.post("/malware/new")
async def create_standalone_malware(
    name: str = Form(...),
    family: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
    event_id: Optional[int] = Form(None),
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
    session.add(malware)
    session.commit()
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
    template = env.get_template("phish/standalone_form.html")
    return template.render(request=request, phish=None, events=events, action="/phishing/new")


@app.post("/phishing/new")
async def create_standalone_phish(
    subject: Optional[str] = Form(None),
    sender: Optional[str] = Form(None),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    risk_level: Optional[str] = Form(None),
    occurrence_date: Optional[str] = Form(None),
    event_id: Optional[int] = Form(None),
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
    session.add(phish)
    session.commit()
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
    
    template = env.get_template("settings.html")
    return template.render(request=request, stats=stats, db_info=db_info, families=families)


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
