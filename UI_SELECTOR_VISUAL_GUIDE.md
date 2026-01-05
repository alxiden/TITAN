# New Report Selector UI - Visual Guide

## Selector Layout

```
┌────────────────────────────────────────────────────────────┐
│         Generate Custom Report                            │
│                                                             │
│  ┌─────────────────────┐  ┌─────────────────────┐         │
│  │ Target Audience     │  │ Report Period       │         │
│  │                     │  │                     │         │
│  │ [Exec ▼]           │  │ [Period Type ▼]    │         │
│  │ - Executive Lead... │  │ - Month            │         │
│  │ - IT/Technical Team │  │ - Quarter          │         │
│  │ - End Users        │  │ - Year             │         │
│  └─────────────────────┘  └─────────────────────┘         │
│                                                             │
│  ┌─────────────────────┐  ┌─────────────────────┐         │
│  │ Select Month        │  │                     │         │
│  │ (Hidden until       │  │                     │         │
│  │  Month is selected) │  │                     │         │
│  │                     │  │                     │         │
│  │ [Month ▼]          │  │                     │         │
│  │ - January          │  │ [Generate Report]  │         │
│  │ - February         │  │                     │         │
│  │ - ...              │  │                     │         │
│  │ - December         │  │                     │         │
│  └─────────────────────┘  └─────────────────────┘         │
│                                                             │
│  Alternative: Period Type = Quarter                       │
│  ┌─────────────────────┐                                   │
│  │ Select Quarter      │                                   │
│  │                     │                                   │
│  │ [Quarter ▼]        │                                   │
│  │ - Q1 (Jan-Mar)     │                                   │
│  │ - Q2 (Apr-Jun)     │                                   │
│  │ - Q3 (Jul-Sep)     │                                   │
│  │ - Q4 (Oct-Dec)     │                                   │
│  └─────────────────────┘                                   │
│                                                             │
│  Alternative: Period Type = Year                         │
│  ┌─────────────────────┐                                   │
│  │ Select Year         │                                   │
│  │                     │                                   │
│  │ [Year ▼]           │                                   │
│  │ - 2024             │                                   │
│  │ - 2025             │                                   │
│  │ - 2026             │                                   │
│  └─────────────────────┘                                   │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

## User Interaction Flow

### Step 1: Select Audience
```
User clicks: Target Audience dropdown
             ↓
Shows three options:
┌─────────────────────────────┐
│ ○ Executive Leadership      │
│ ○ IT/Technical Team        │
│ ○ End Users                │
└─────────────────────────────┘
User selects: Executive Leadership
```

### Step 2: Select Period Type
```
User clicks: Report Period dropdown
             ↓
Shows three options:
┌─────────────────────────────┐
│ ○ Month                      │
│ ○ Quarter                    │
│ ○ Year                       │
└─────────────────────────────┘
User selects: Month
             ↓
monthSelectorDiv appears
```

### Step 3: Select Specific Period
```
User clicks: Select Month dropdown
             ↓
Shows month options:
┌─────────────────────────────┐
│ □ January                   │
│ □ February                  │
│ □ March                     │
│ ...                         │
│ □ December                  │
└─────────────────────────────┘
User selects: January
```

### Step 4: Generate Report
```
User clicks: Generate Report button
             ↓
Button shows: ⏳ Generating...
Button disabled: true
             ↓
API call: /api/reports/generate?
          audience=exec&
          period_type=month&
          period=01
             ↓
Backend processes (< 1 second)
             ↓
Button shows: 📋 Generate Report
Button disabled: false
             ↓
Report displays:
┌───────────────────────────────────────┐
│ Report Header                         │
│ Period: January 2026                  │
│ Generated: Jan 5, 2026 3:45 PM UTC   │
├───────────────────────────────────────┤
│ Executive Summary...                  │
│                                       │
│ [Trend Chart - Daily for Month]       │
│                                       │
│ [Top Threats, APTs, etc...]          │
└───────────────────────────────────────┘
```

## Conditional Display Logic (JavaScript)

```javascript
// Initial state - all sub-selectors hidden
monthSelectorDiv.style.display = 'none'
yearSelectorDiv.style.display = 'none'
quarterSelectorDiv.style.display = 'none'

// User changes period type
timePeriodSelect.addEventListener('change', function() {
  // Hide all first
  monthSelectorDiv.style.display = 'none'
  yearSelectorDiv.style.display = 'none'
  quarterSelectorDiv.style.display = 'none'
  
  // Show relevant one
  if (this.value === 'month') {
    monthSelectorDiv.style.display = 'block'
  } else if (this.value === 'year') {
    yearSelectorDiv.style.display = 'block'
  } else if (this.value === 'quarter') {
    quarterSelectorDiv.style.display = 'block'
  }
})
```

## State Management

```
┌──────────────────────────────────────────────────────┐
│           USER STATE TRACKING                         │
├──────────────────────────────────────────────────────┤
│                                                      │
│  audienceSelect.value = ""      [Initial]           │
│  timePeriodSelect.value = ""    [Initial]           │
│  monthSelect.value = ""         [Initial]           │
│  quarterSelect.value = ""       [Initial]           │
│  yearSelect.value = ""          [Initial]           │
│                                                      │
│  After User Selections:                             │
│  audienceSelect.value = "exec"  [User selected]     │
│  timePeriodSelect.value = "month" [User selected]   │
│  monthSelect.value = "01"       [User selected]     │
│                                                      │
│  All three values required for "Generate":          │
│  if (!audience || !periodType || !period)           │
│      alert('Please select all fields')              │
│                                                      │
└──────────────────────────────────────────────────────┘
```

## Report Header Changes

### Old Format (30/60/90 Days)
```
Security Executive Report
Report Period: Last 30 Days
Generated: January 5, 2026 at 3:45 PM UTC
```

### New Format (Month/Quarter/Year)
```
Security Executive Report
Report Period: January 2026
Generated: January 5, 2026 at 3:45 PM UTC
```

```
Security Executive Report
Report Period: Q2 2026
Generated: January 5, 2026 at 3:45 PM UTC
```

```
Security Executive Report
Report Period: 2026
Generated: January 5, 2026 at 3:45 PM UTC
```

## Trend Chart Data Format

### Monthly Report
```
X-Axis Labels: 01/01, 01/02, 01/03, ... 01/31
Y-Axis: Count (0-N)
Bars: Malware (blue) vs Phishing (red)
Pattern: Shows daily pattern within the month
```

### Quarterly Report
```
X-Axis Labels: 01/01, 01/06, 01/11, 01/16, ... 06/30
Y-Axis: Count (0-N)
Bars: Malware (blue) vs Phishing (red)
Pattern: Every 5th day shown (to avoid crowding)
Total Points: ~90
```

### Yearly Report
```
X-Axis Labels: 01/01, 01/06, 01/11, ... 12/31
Y-Axis: Count (0-N)
Bars: Malware (blue) vs Phishing (red)
Pattern: Every 5th day shown
Total Points: ~365
```

## Download Filename Format

### Old Format
```
TITAN_Report_exec_30days_2026-01-05.html
TITAN_Report_it_60days_2026-01-05.html
TITAN_Report_users_90days_2026-01-05.html
```

### New Format
```
TITAN_Report_exec_January_2026-01-05.html
TITAN_Report_it_Q2_2026-01-05.html
TITAN_Report_users_2026_2026-01-05.html
```

## Validation Flow

```
┌────────────────────────────────────────┐
│  User clicks "Generate Report"        │
└──────────────┬───────────────────────┘
               │
               ▼
       ┌─────────────────┐
       │ Get form values │
       │ audience        │
       │ periodType      │
       │ period          │
       └────────┬────────┘
                │
    ┌───────────┴───────────┐
    │                       │
    ▼                       ▼
Any null or     All values
empty values?   present?
    │                │
    │ YES             │ NO
    │                 │
    ▼                 ▼
Show Alert      Disable button
"Select all"    Show loading
                "⏳ Generating..."
                        │
                        ▼
                  Call API with:
                  audience=X
                  period_type=Y
                  period=Z
                        │
                        ▼
                  Backend processes
                        │
                        ▼
                  Return HTML
                        │
                        ▼
                  Display report
                  Enable button
                  "📋 Generate"
```

## Summary

| Aspect | Details |
|--------|---------|
| **Main Selectors** | Audience + Period Type |
| **Sub Selectors** | Month/Quarter/Year (conditional) |
| **Month Option** | Dropdown 1-12 |
| **Quarter Option** | Dropdown Q1-Q4 |
| **Year Option** | Dropdown 2024-2026 |
| **Validation** | All three selections required |
| **Chart Data** | Daily data (auto-formatted labels) |
| **Report Header** | Shows period_label (e.g., "January 2026") |
| **Download Name** | Includes period value |
| **Data Range** | Exact month/quarter/year dates |
