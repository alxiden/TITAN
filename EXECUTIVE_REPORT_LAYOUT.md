# Executive Report Layout - Enhanced Version

## Report Sections Overview

```
┌─────────────────────────────────────────────────────────┐
│                     REPORT HEADER                       │
│  Title: Security Executive Report                       │
│  Period: Last {30/60/90} Days                           │
│  Generated: [Timestamp]                                 │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                 EXECUTIVE SUMMARY                       │
│  Brief introduction explaining the report purpose       │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│               KEY METRICS (Dashboard)                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ 47       │  │ 12       │  │ 35       │  │ 8      │ │
│  │ TOTAL    │  │ OPEN     │  │ RESOLVED │  │ CRIT/  │ │
│  │ EVENTS   │  │ EVENTS   │  │ EVENTS   │  │ HIGH   │ │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘ │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│        THREAT TREND ANALYSIS (MONTHLY)                  │
│                                                          │
│    ││   ││   ││   ││                                    │
│    ││█  ││   ││█  ││█  ││   ││█                       │ (Chart)
│    ││█  ││█  ││█  ││█  ││█  ││█  ││█                 │
│    ├─┼──┼────┼────┼────┼────┼────┼──┤                 │
│    0 Nov Dec Jan Feb Mar Apr May Jun                    │
│                                                          │
│    ■ Malware Detections (Blue)                         │
│    ■ Phishing Attempts (Red)                           │
│                                                          │
│    Trend Insight: Chart shows month-over-month trends   │
│    to identify seasonal patterns and assess security    │
│    measure effectiveness.                               │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│              THREAT OVERVIEW                            │
│  • Malware Incidents: 23                                │
│  • Phishing Attempts: 45                                │
│                                                          │
│  Severity Distribution:                                 │
│  ┌─────────┬─────────┬─────────┬─────────┐            │
│  │Critical │   High  │ Medium  │   Low   │            │
│  │    2    │    6    │   15    │   24    │            │
│  └─────────┴─────────┴─────────┴─────────┘            │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│     MOST TARGETED AREAS/DEPARTMENTS                     │
│                                                          │
│  ┌──────────────────────┬────────────┐                 │
│  │ Target Area          │ Incidents  │                 │
│  ├──────────────────────┼────────────┤                 │
│  │ Finance Department   │     18     │                 │
│  │ C-Suite/Executives   │     12     │                 │
│  │ HR Department        │      8     │                 │
│  │ Engineering Team     │      5     │                 │
│  │ Operations           │      4     │                 │
│  └──────────────────────┴────────────┘                 │
│                                                          │
│  Note: These are the departments most frequently        │
│  targeted by phishing attacks. Consider enhanced        │
│  security awareness training for these areas.           │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│      KNOWN THREAT ACTORS (APTs)                         │
│                                                          │
│  The following Advanced Persistent Threat (APT)         │
│  groups have been identified in your environment:       │
│                                                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │ ⚠ APT41 (Winnti)                               │   │
│  │   Associated with 8 incident(s)                  │   │
│  └─────────────────────────────────────────────────┘   │
│                                                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │ ⚠ Lazarus Group                                │   │
│  │   Associated with 5 incident(s)                  │   │
│  └─────────────────────────────────────────────────┘   │
│                                                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │ ⚠ APT29 (Cozy Bear)                            │   │
│  │   Associated with 3 incident(s)                  │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│            TOP THREATS                                  │
│                                                          │
│  Top Malware Families    │  Top Phishing Senders        │
│  ┌──────────┬────────┐  │  ┌──────────┬────────┐       │
│  │ Emotet   │   12   │  │  │ domain.ru│   8    │       │
│  │ TrickBot │    8   │  │  │ fake.com │   6    │       │
│  │ Dridex   │    5   │  │  │ sender.cn│   4    │       │
│  │ Zloader  │    3   │  │  │ phish.org│   3    │       │
│  │ Qbot     │    2   │  │  │ spoof.io │   2    │       │
│  └──────────┴────────┘  │  └──────────┴────────┘       │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│           RECOMMENDATIONS                               │
│                                                          │
│ • Review open and unresolved security incidents for     │
│   immediate action                                      │
│                                                          │
│ • Increase monitoring for detected malware families     │
│   and APT groups                                        │
│                                                          │
│ • Implement targeted security awareness training for    │
│   Finance and C-Suite (most targeted groups)           │
│                                                          │
│ • Consider threat intelligence integration for early    │
│   warning of APT activities                            │
│                                                          │
│ • Review and strengthen email security controls to      │
│   reduce phishing attempts                             │
│                                                          │
│ • Develop incident response playbooks specific to       │
│   identified APT tactics                               │
└─────────────────────────────────────────────────────────┘
```

## New Data Visualizations

### 1. Threat Trend Chart
- **Type**: SVG Bar Chart
- **X-Axis**: Months (Nov, Dec, Jan, etc.)
- **Y-Axis**: Incident Count (0-N)
- **Bars**: Grouped (Malware left, Phishing right)
- **Colors**: 
  - Blue (#1a73e8) = Malware
  - Red (#d93025) = Phishing
- **Features**: Grid lines, labeled axes, legend

### 2. Targeted Areas Table
- **Columns**: Target Area/Department | Incidents
- **Rows**: Top 5 most targeted
- **Sorting**: By incident count (descending)
- **Footer**: Actionable insight about training

### 3. Known APTs Section
- **Style**: Red alert boxes
- **Format**: One APT per box with incident count
- **Maximum**: Top 5 APTs
- **Styling**: Left border accent for emphasis
- **Info**: Incident count for context

## Information Flow

```
User selects:
  - Audience: "Executive"
  - Period: "30 days" → API Call
  
API processes:
  - Fetches all events/malware/phishing in period
  - Groups by severity, status, type
  - Creates monthly buckets
  - Aggregates APT associations
  - Extracts unique target areas

Report generates:
  1. Summary metrics
  2. SVG trend chart
  3. Targeted areas table
  4. APT threat cards
  5. Top threat tables
  6. Strategic recommendations

Output:
  - Formatted HTML
  - Ready to view or download
  - Includes styling
  - Print-ready
```

## Key Insights Generated

For each report:
- **Trend**: Are threats increasing or decreasing?
- **Focus**: Which departments need attention?
- **Actors**: Who is attacking us?
- **Action**: What should we do?

## Executive Value Proposition

| Question | Answered By |
|----------|------------|
| Are our threats increasing? | Trend Chart |
| Where are attacks happening? | Targeted Areas |
| Who is attacking us? | Known APTs |
| What's the severity? | Key Metrics |
| What should we do? | Recommendations |
