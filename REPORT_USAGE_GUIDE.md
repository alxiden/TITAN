## Custom Report Generator - Quick Start Guide

### How It Works

```
User Action Flow:
┌─────────────────────────────────────────┐
│  1. Navigate to /reports page           │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│  2. Locate "Generate Custom Report"     │
│     section at the top of the page      │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│  3. Select:                             │
│     - Audience (Exec/IT/Users)          │
│     - Time Period (30/60/90 days)       │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│  4. Click "Generate Report" button      │
└────────────────┬────────────────────────┘
                 │
    ┌────────────┴────────────┐
    │                         │
    ▼                         ▼
Server Processing      User Sees:
• Query database      ⏳ "Generating..."
• Aggregate data
• Format HTML
    │
    └────────────┬────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│  5. View formatted report               │
│     - Key metrics                       │
│     - Threat analysis                   │
│     - Recommendations                   │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│  6. Optional: Download as HTML          │
│     - Saves to local computer           │
│     - Formatted for printing            │
└─────────────────────────────────────────┘
```

### Report Content by Audience

**Executive Report (Exec)**
```
┌─ High-Level Overview
├─ Key Metrics
│  ├─ Total Events
│  ├─ Open vs Resolved
│  └─ Critical/High Priority Count
├─ Threat Overview
│  ├─ Malware Incident Count
│  └─ Phishing Attempt Count
├─ Top Threats
│  ├─ Malware Families
│  └─ Phishing Senders
└─ Recommendations for Leadership
```

**IT Report (Technical Team)**
```
┌─ Incident Summary
├─ Statistics
│  ├─ Total Incidents
│  ├─ Status Breakdown (Open/In Progress/Resolved)
│  └─ Severity Distribution (Critical/High/Medium/Low)
├─ Incident Types
├─ Threat Analysis
│  ├─ Malware Detection Details
│  └─ Phishing Detection Details
└─ Technical Recommendations
```

**User Report (End Users)**
```
┌─ Security Awareness
├─ Key Threats
│  ├─ Phishing Attempts Blocked
│  └─ Critical Alerts
├─ Protection Guidance
│  ├─ Phishing Prevention
│  ├─ Password Security
│  └─ Contact Information
└─ Summary & Thank You
```

### Data Points Collected

From **Events Table**:
- Total count
- Status distribution (open, in-progress, resolved)
- Severity distribution (critical, high, medium, low)
- Type distribution

From **Malware Table**:
- Total count
- Family distribution (top 5)
- Linked to events

From **Phishing Table**:
- Total count
- Sender distribution (top 5)
- Linked to events

### Time Periods Supported
- 30 days
- 60 days
- 90 days

### API Endpoint Details

**Endpoint**: `GET /api/reports/generate`

**Query Parameters**:
```
audience=<exec|it|users>  (required)
days=<30|60|90>          (required)
```

**Example Request**:
```
GET /api/reports/generate?audience=exec&days=30
```

**Response Format**:
```json
{
  "html": "<div class='report-header'>...</div><h2>...</h2>..."
}
```

### Browser Compatibility
- All modern browsers (Chrome, Firefox, Safari, Edge)
- Mobile responsive
- Print-friendly styling

### Download File Format
- Format: HTML
- Filename: `TITAN_Report_<audience>_<days>days_YYYY-MM-DD.html`
- Can be opened in any browser
- Includes complete styling

---

**Example Filenames**:
- `TITAN_Report_exec_30days_2026-01-05.html`
- `TITAN_Report_it_60days_2026-01-05.html`
- `TITAN_Report_users_90days_2026-01-05.html`
