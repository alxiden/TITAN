# Custom Report Generator Feature

## Overview
A new report generation feature has been added to the TITAN Reports page, allowing users to generate customized reports based on:
- **Target Audience**: Executive Leadership, IT/Technical Team, or End Users
- **Time Period**: Last 30, 60, or 90 days

## Features Implemented

### 1. Frontend (reports.html)
- **New UI Section**: "Generate Custom Report" section with clean dropdown selectors
- **Controls**:
  - Audience selector (Exec, IT, Users)
  - Time period selector (30, 60, 90 days)
  - Generate Report button
  - Download as HTML button

- **Report Output**: 
  - Real-time report generation display
  - HTML report with formatted styling
  - Download capability for local storage

### 2. Backend API Endpoints

#### `/api/reports/generate` (GET)
**Parameters:**
- `audience` (string): "exec", "it", or "users"
- `days` (integer): 30, 60, or 90

**Returns:**
- JSON response with formatted HTML report

**Response Format:**
```json
{
  "html": "<formatted HTML report>"
}
```

### 3. Report Types

#### Executive Report (Audience: Exec)
- High-level summary of security posture
- Key metrics (total events, open events, resolved events, critical/high priority)
- Threat overview (malware and phishing counts)
- Top threats (malware families and phishing senders)
- Executive recommendations
- **Focus**: Strategic overview for decision-making

#### IT/Technical Report (Audience: IT)
- Detailed incident statistics
- Status breakdown (open, in-progress, resolved)
- Severity breakdown (critical, high, medium, low)
- Incident types distribution
- Threat analysis with technical details
- Top malware families and phishing senders
- Recommended technical actions
- **Focus**: Operational details for incident response teams

#### User Awareness Report (Audience: Users)
- Security posture summary in non-technical language
- Key threats highlighted
- Phishing awareness guidance
- Password security best practices
- Contact information for security team
- Summary of prevented incidents
- **Focus**: Education and awareness for end users

## Data Aggregation

The report generator collects and analyzes:
- **Events**: Filtered by creation date within the selected period
  - Count by status (open, in-progress, resolved)
  - Count by severity (critical, high, medium, low)
  - Count by type (phishing, malware, breach, etc.)

- **Malware**: Filtered by creation or occurrence date
  - Total count
  - Family distribution
  - Top 5 families by occurrence

- **Phishing**: Filtered by creation or occurrence date
  - Total count
  - Sender distribution
  - Top 5 senders by attempts

## Usage

1. Navigate to the Reports page (`/reports`)
2. Scroll to the "Generate Custom Report" section
3. Select an audience (Exec, IT, or Users)
4. Select a time period (30, 60, or 90 days)
5. Click "Generate Report"
6. Review the formatted report
7. Optionally, click "Download as HTML" to save the report

## Technical Implementation

### Database Queries
- Uses SQLAlchemy ORM to query events, malware, and phishing data
- Filters data based on `created_at` and `occurrence_date` fields
- Efficiently aggregates related data through relationships

### HTML Report Generation
- Server-side HTML generation with embedded styling
- Bootstrap CSS framework for responsive design
- Clean, professional formatting
- Print-friendly styles

### Client-Side Features
- Asynchronous report generation (non-blocking UI)
- Real-time status feedback to user
- HTML export with timestamp and metadata
- Responsive design for all screen sizes

## File Changes

1. **frontend/templates/reports.html**
   - Added custom report generator UI section
   - Added JavaScript event handlers
   - Added report download functionality

2. **backend/api.py**
   - Added `/api/reports/generate` endpoint
   - Added helper functions:
     - `generate_executive_report()`
     - `generate_it_report()`
     - `generate_users_report()`

## Testing

The implementation has been validated for:
- ✓ Module imports
- ✓ FastAPI app initialization
- ✓ Database connectivity
- ✓ No syntax errors
- ✓ HTML/CSS rendering
- ✓ JavaScript functionality

## Future Enhancements

Potential improvements:
- PDF export functionality
- Email delivery of reports
- Scheduled report generation
- Custom report templates
- Data visualization charts in reports
- Filtering by specific event types or severity
- Comparison reports (period-over-period)
- Metric trending
