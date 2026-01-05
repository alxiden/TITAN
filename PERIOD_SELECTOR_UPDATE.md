# Report Period Enhancement - Month/Quarter/Year Selector

## Summary of Changes

The report generation system has been updated to support flexible time periods instead of fixed 30/60/90 day windows. Users can now generate reports for:

- **Specific Months** (with dropdown selector for January-December)
- **Quarters** (Q1, Q2, Q3, Q4)
- **Years** (2024, 2025, 2026, etc.)

## Frontend Changes (reports.html)

### UI Updates
```html
<!-- Main Period Type Selector -->
<select id="timePeriodSelect">
  <option value="month">Month</option>
  <option value="quarter">Quarter</option>
  <option value="year">Year</option>
</select>

<!-- Conditional Sub-Selectors (shown/hidden based on period type) -->
<div id="monthSelectorDiv">        <!-- Month dropdown -->
<div id="quarterSelectorDiv">      <!-- Quarter dropdown -->
<div id="yearSelectorDiv">         <!-- Year dropdown -->
```

### JavaScript Features
- Event listener on `timePeriodSelect` to show/hide relevant sub-selectors
- Dynamic API calls with `period_type` and `period` parameters
- Updated download filename to reflect selected period
- Month name translation for display

## Backend Changes (api.py)

### API Endpoint Update
**Old**: `GET /api/reports/generate?audience=<audience>&days=<days>`
**New**: `GET /api/reports/generate?audience=<audience>&period_type=<type>&period=<value>`

### Parameter Handling
```python
period_type: str  # "month", "quarter", or "year"
period: str       # "01" (month), "Q1" (quarter), or "2026" (year)

# Results in period_label like:
# "January 2026", "Q1 2026", "2026"
```

### Date Range Calculations
- **Month**: Full month (1st to last day)
- **Quarter**: 3-month period (Q1: Jan-Mar, Q2: Apr-Jun, etc.)
- **Year**: Full calendar year (Jan 1 - Dec 31)

### Trend Data Improvements
Changed from **monthly_malware/monthly_phishing** to **daily_malware/daily_phishing**:
- More granular trend visualization
- Works for all period types (month, quarter, year)
- Automatic label formatting:
  - For month data: Shows all dates (01/01, 01/02, etc.)
  - For longer periods: Shows every 5th date to avoid crowding

### Report Generation Functions Updated
1. `generate_executive_report(period_label, ...)` - Uses period_label instead of days
2. `generate_it_report(period_label, ...)` - Uses period_label instead of days
3. `generate_users_report(period_label, ...)` - Uses period_label instead of days

### Trend Chart Function Enhanced
```python
def generate_trend_chart(trend_data):
    # Detects if data contains 'date' or 'month' keys
    # Automatically formats labels appropriately
    # For long date ranges (>12 points), shows every 5th label
    # Wider SVG (900px) to accommodate more data points
```

## Data Flow

```
User Selection:
  Period Type: "Month" → Sub-selector shows month dropdown
               "Quarter" → Sub-selector shows quarter dropdown
               "Year" → Sub-selector shows year dropdown

  User selects specific value:
  - Month: "01" (January)
  - Quarter: "Q2"
  - Year: "2026"

API Call:
  /api/reports/generate?audience=exec&period_type=month&period=01

Backend Processing:
  1. Validates period_type and period values
  2. Calculates window_start and window_end dates
  3. Creates period_label (e.g., "January 2026")
  4. Queries database for events/malware/phishing in range
  5. Aggregates by day instead of month
  6. Generates trend chart with properly ordered dates
  7. Returns HTML report with period_label

Frontend Display:
  - Report header shows "January 2026" (not "Last 30 Days")
  - Trend chart shows daily data for the month
  - All references use period_label
```

## Examples

### Scenario 1: Executive Monthly Report
```
1. Select Audience: Executive Leadership
2. Select Period Type: Month
3. Month dropdown shows: January, February, March... December
4. Select: January
5. Report generated for January 1-31, 2026
   Header: "Report Period: January 2026"
   Chart: Shows malware/phishing for each day in January
```

### Scenario 2: IT Quarterly Report
```
1. Select Audience: IT/Technical Team
2. Select Period Type: Quarter
3. Quarter dropdown shows: Q1, Q2, Q3, Q4
4. Select: Q2 (April-June)
5. Report generated for April 1 - June 30, 2026
   Header: "Report Period: Q2 2026"
   Chart: Shows daily trends across 3-month period
```

### Scenario 3: User Yearly Report
```
1. Select Audience: End Users
2. Select Period Type: Year
3. Year dropdown shows: 2024, 2025, 2026
4. Select: 2026
5. Report generated for January 1 - December 31, 2026
   Header: "Report Period: 2026"
   Chart: Shows trends with selective labels (every 5th day)
```

## Benefits

| Aspect | Benefit |
|--------|---------|
| **Flexibility** | Users can select any month, quarter, or year |
| **Precision** | Month reports are more focused than 30 days |
| **Business Alignment** | Quarters align with business reporting cycles |
| **Proper Sorting** | Dates are chronologically ordered (not alphabetical) |
| **Cleaner Labels** | Reports say "January 2026" instead of "Last 30 Days" |
| **Scalable Visualization** | Chart automatically handles different time scales |

## Technical Details

### Month Validation
```python
# "01" to "12" are valid
if not (1 <= month_num <= 12):
    return error
```

### Quarter Mapping
```
"Q1" → January 1 to March 31
"Q2" → April 1 to June 30
"Q3" → July 1 to September 30
"Q4" → October 1 to December 31
```

### Year Validation
```python
# 2000-2100 range (extensible)
if not (2000 <= year <= 2100):
    return error
```

### Date Range Queries
```python
# Uses start AND end date in filters
filter((Entity.created_at >= window_start) & (Entity.created_at < window_end))
```

## UI Responsiveness

- Selectors hide/show dynamically via JavaScript
- No page reload needed when changing period type
- Smooth transitions between selector visibility
- Mobile-friendly dropdown interface

## Future Enhancements

- Add "Custom Date Range" option for arbitrary date selection
- Add year selector range for multi-year comparisons
- Add "Last N months" option for rolling windows
- Add preset buttons (e.g., "YTD", "Last Quarter", "Previous Month")
- Export to multiple formats (PDF, Excel, CSV)

## Backward Compatibility

⚠️ **Breaking Change**: The API endpoint parameters have changed from:
```
GET /api/reports/generate?audience=X&days=Y
```
To:
```
GET /api/reports/generate?audience=X&period_type=Z&period=A
```

Old bookmarks or API calls will no longer work. Frontend has been updated to use new parameters.

## Testing Recommendations

1. ✅ Test each period type (month, quarter, year)
2. ✅ Test edge cases (December month, Q4 quarter, year 2026)
3. ✅ Verify date sorting in trend chart
4. ✅ Check label visibility for long-date ranges
5. ✅ Test across all audience types (exec, it, users)
6. ✅ Verify download filename format
