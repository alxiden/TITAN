# Executive Report Enhancements

## Overview
The Executive Report has been significantly enhanced with trend analysis, targeted area identification, and APT threat actor tracking.

## New Features Added

### 1. **Month-over-Month Trend Analysis**
- **Visual Representation**: SVG-based bar chart showing malware and phishing trends
- **Time-Based Tracking**: Groups incidents by month across the selected period
- **Dual Metrics**: Displays both malware detections and phishing attempts on the same chart
- **Color Coding**: 
  - Blue bars = Malware detections
  - Red bars = Phishing attempts
- **Interactive Legend**: Shows what each color represents
- **Insights**: Includes explanatory text about seasonal patterns and security measure effectiveness

### 2. **Most Targeted Areas/Departments**
- **Data Source**: Extracted from phishing target field in database
- **Ranking**: Automatically ranks departments by number of phishing incidents
- **Top 5 Display**: Shows the 5 most-targeted areas
- **Actionable Insights**: Includes recommendation for enhanced security awareness training for high-risk areas
- **Table Format**: Clean, easy-to-read table with incident counts

### 3. **Known Threat Actors (APTs)**
- **Automatic Detection**: Identifies APTs linked to events, malware, and phishing incidents
- **Association Counting**: Shows how many incidents are linked to each APT
- **Top Threat Actors**: Displays up to 5 most active APTs
- **Visual Highlighting**: Red-highlighted alert boxes to emphasize threat severity
- **Contextual Information**: Helps executives understand which threat actors are targeting their organization

## Technical Implementation

### Data Collection
The enhanced report now collects:

```python
# Month-over-month trends
monthly_malware = defaultdict(int)  # Grouped by month
monthly_phishing = defaultdict(int)  # Grouped by month

# Targeted areas
targeted_areas = {}  # From Phish.target field

# Associated APTs
apt_associations = {}  # From Event/Malware/Phish.apts relationships
```

### SVG Chart Generation
- **Dynamic Scaling**: Automatically scales to data range
- **Grid Lines**: 5-line grid for easy value reading
- **Labeled Axes**: X-axis (months) and Y-axis (count) labeled
- **Responsive**: Adapts to different data sizes
- **Browser Compatible**: Works in all modern browsers

### Report Structure (Updated)
```
1. Header (Report Period & Generation Time)
2. Executive Summary
3. Key Metrics (Dashboard View)
4. Threat Trend Analysis [NEW - Visual Chart]
5. Threat Overview
6. Most Targeted Areas [NEW - Table]
7. Known Threat Actors [NEW - Highlighted Boxes]
8. Top Threats (Malware & Phishing)
9. Recommendations [ENHANCED]
```

## Data Points Tracked

### Trend Analysis
- Historical data for last N days (30, 60, or 90)
- Monthly aggregation of malware and phishing incidents
- Identifies patterns and seasonal variations

### Targeted Areas
- Department/team names from phishing target field
- Frequency count for each target
- Identifies high-risk groups

### APT Associations
- All APTs linked to events in the period
- All APTs linked to malware samples
- All APTs linked to phishing campaigns
- Incident count per APT
- Helps identify active threat campaigns

## Usage Example

When an executive generates a report for the last 90 days:

1. **Chart** shows a clear trend line of malware vs phishing over the 3 months
2. **Table** reveals that "Finance Department" and "C-Suite" are most targeted
3. **APT Section** indicates "APT41" and "Lazarus Group" have been active against the organization

This enables executives to:
- Understand threat trends and patterns
- Allocate resources to high-risk departments
- Prioritize defense against identified threat actors
- Make data-driven security strategy decisions

## Benefits

| Feature | Benefit |
|---------|---------|
| Trend Chart | Visualize threat trajectory and patterns |
| Targeted Areas | Identify which departments need enhanced training |
| APT Tracking | Understand which threat actors are active |
| Executive Focus | All information presented at strategic level |
| Actionable Data | Clear recommendations based on findings |

## Future Enhancements

Potential additions to executive reports:
- Yearly trends and historical comparison
- Cost impact analysis of incidents
- ROI calculations for security investments
- Peer benchmark comparisons
- Threat actor profile cards
- Attack vector distribution
- Timeline of major incidents
