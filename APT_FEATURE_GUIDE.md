# TITAN APT Management Feature

## Overview

The APT (Advanced Persistent Threat) management feature has been added to TITAN, allowing you to:

- Create and manage APT profiles with detailed information
- Link APTs to Security Events, Malware, Phishing campaigns, and IOCs
- Track APT activity across your entire threat intelligence database
- Generate reports and analytics on APT activities

## Database Schema

### APT Model (`apts` table)

```sql
CREATE TABLE apts (
  id INTEGER PRIMARY KEY,
  name VARCHAR(256) NOT NULL UNIQUE,
  aliases TEXT,                    -- Comma-separated aliases/variants
  description TEXT,                -- Detailed description
  country_origin VARCHAR(128),     -- Country of origin/attribution
  primary_targets TEXT,            -- Comma-separated list of primary targets
  tactics TEXT,                    -- MITRE ATT&CK tactics (comma-separated)
  techniques TEXT,                 -- MITRE ATT&CK techniques (comma-separated)
  first_seen DATETIME,             -- First known activity
  last_seen DATETIME,              -- Last known activity
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

### Association Tables (Many-to-Many)

The following association tables link APTs to other entities:

- **apt_events**: Links APTs to Events
- **apt_malware**: Links APTs to Malware instances
- **apt_phishing**: Links APTs to Phishing campaigns
- **apt_iocs**: Links APTs to Indicators of Compromise

These tables automatically cascade deletes when APT relationships are modified.

## Web Interface

### Routes

#### APT Management
- **GET `/apts`** - List all APTs with search functionality
- **GET `/apts/{id}`** - View detailed APT profile with all linked entities
- **GET `/apts/new/form`** - Display form to create new APT
- **POST `/apts/new`** - Create new APT
- **GET `/apts/{id}/edit`** - Display form to edit APT
- **POST `/apts/{id}/edit`** - Update APT details
- **POST `/apts/{id}/delete`** - Delete APT record

#### APT Linking/Unlinking
- **POST `/apts/{apt_id}/link/event/{event_id}`** - Link APT to an Event
- **POST `/apts/{apt_id}/unlink/event/{event_id}`** - Unlink APT from an Event
- **POST `/apts/{apt_id}/link/malware/{malware_id}`** - Link APT to Malware
- **POST `/apts/{apt_id}/unlink/malware/{malware_id}`** - Unlink APT from Malware
- **POST `/apts/{apt_id}/link/phish/{phish_id}`** - Link APT to Phishing
- **POST `/apts/{apt_id}/unlink/phish/{phish_id}`** - Unlink APT from Phishing
- **POST `/apts/{apt_id}/link/ioc/{ioc_id}`** - Link APT to IOC
- **POST `/apts/{apt_id}/unlink/ioc/{ioc_id}`** - Unlink APT from IOC

### API Endpoints (JSON)

- **GET `/api/apts`** - Get all APTs as JSON with counts
- **GET `/api/apts/{id}`** - Get detailed APT information as JSON
- **GET `/api/charts/apts-top`** - Get top APTs by activity (with date range filtering)

## Features

### Creating an APT

1. Navigate to **APTs** from the home page
2. Click **+ Add APT**
3. Fill in the following fields:
   - **APT Name*** (required) - Primary name/designation
   - **Aliases** - Alternative names (comma-separated)
   - **Description** - Detailed information about the APT
   - **Country of Origin** - Attribution information
   - **Primary Targets** - Industry/sector targets (comma-separated)
   - **MITRE ATT&CK Tactics** - Applicable tactics (comma-separated)
   - **MITRE ATT&CK Techniques** - Specific techniques (comma-separated)
   - **First Seen** - Date of first known activity
   - **Last Seen** - Date of last known activity
4. Click **Create APT**

### Editing an APT

1. Navigate to the APT detail page
2. Click **Edit**
3. Modify the desired fields
4. Click **Update APT**

### Linking APTs to Other Entities

#### From Event, Malware, or Phishing pages:
You can link APTs directly through the entity's detail page once the linking UI is integrated.

#### Via API:
```bash
# Link APT to Event
POST /apts/{apt_id}/link/event/{event_id}

# Link APT to Malware
POST /apts/{apt_id}/link/malware/{malware_id}

# Link APT to Phishing
POST /apts/{apt_id}/link/phish/{phish_id}

# Link APT to IOC
POST /apts/{apt_id}/link/ioc/{ioc_id}
```

### Viewing APT Details

1. Click on an APT name in the list or search results
2. The detail page shows:
   - Basic APT information
   - All linked Events (with status and severity)
   - All linked Malware (with families and IOCs)
   - All linked Phishing campaigns
   - All linked IOCs
   - Quick-unlink buttons for each linked item

### APT List Features

- **Search**: Real-time filtering by any column
- **Columns**: Name, Aliases, Country, Events, Malware, Phishing, IOCs counts
- **Quick Actions**: Edit or Delete buttons for each APT

## Usage Examples

### Example 1: APT28 Malware Campaign

1. Create APT: "APT28" with aliases "Fancy Bear, Sofacy"
2. Create a Security Event: "APT28 Spear-phishing Campaign"
3. Link the Event to APT28
4. Create Malware entries: "X-Agent", "BlackEnergy"
5. Link the Malware to APT28
6. Create IOCs for detected hashes, C2 servers
7. Link IOCs to APT28
8. View the complete APT28 profile showing all related activities

### Example 2: Tracking Lazarus Group Activity

1. Create APT: "Lazarus" with tactics "Initial Access, Execution, Persistence"
2. Link multiple phishing campaigns
3. Link various malware families (Trojan.Volgmer, etc.)
4. Track all IOCs associated with the group
5. Monitor last_seen date to track group activity over time

## Data Flow

```
APT (Core Entity)
├── Events (1:N via apt_events)
│   ├── Malware (1:N via Event)
│   │   └── IOCs (1:N)
│   └── Phishing (1:N via Event)
│       └── IOCs (1:N)
├── Malware (1:N via apt_malware)
│   └── IOCs (1:N)
├── Phishing (1:N via apt_phishing)
│   └── IOCs (1:N)
└── IOCs (1:N via apt_iocs)
```

## Relationship Model

- **APT ↔ Events**: Many-to-Many (one APT can conduct multiple campaigns; one event can involve multiple APTs)
- **APT ↔ Malware**: Many-to-Many (one APT can use multiple malware; one malware can be used by multiple APTs)
- **APT ↔ Phishing**: Many-to-Many (one APT can run multiple campaigns; one campaign can involve multiple APTs)
- **APT ↔ IOCs**: Many-to-Many (one APT can have many IOCs; one IOC can be associated with multiple APTs)

## Security Considerations

- Deleting an APT record does NOT delete linked Events, Malware, Phishing, or IOCs
- Only the relationship is removed
- All entity data remains intact for historical tracking
- APT names must be unique to prevent duplicate entries

## Templates

The following templates were created:

- `frontend/templates/apts/list.html` - APT list view with search
- `frontend/templates/apts/detail.html` - APT detail page with all relationships
- `frontend/templates/apts/new.html` - Form to create new APT
- `frontend/templates/apts/edit.html` - Form to edit existing APT

## Analytics

The following charts/endpoints are available:

- **Top APTs Chart** (`/api/charts/apts-top`) - Shows most active APTs within a date range
- APT count displayed on homepage dashboard
- Event/Malware/Phishing/IOC counts available through each APT's detail page

## Future Enhancements

Possible future improvements:

1. Direct linking UI from Event/Malware/Phishing/IOC detail pages
2. Advanced APT grouping and family trees
3. APT Timeline visualization
4. Custom APT attributes/tags
5. APT threat level scoring
6. Import/Export APT profiles
7. Integration with external threat intelligence feeds
8. Automated APT attribution based on IOC/malware patterns
9. APT infrastructure mapping
10. Bulk linking operations

## Integration Points

The APT feature integrates with:

- **Events**: Display linked APTs in event detail, filter events by APT
- **Malware**: Show APT attribution for malware samples
- **Phishing**: Link phishing campaigns to APTs
- **IOCs**: Associate IOCs with APTs for quick threat lookup
- **Reports**: Include APT activity in threat reports
- **Analytics**: Display APT activity trends and statistics

## API Response Examples

### Get All APTs
```json
GET /api/apts

[
  {
    "id": 1,
    "name": "APT28",
    "aliases": "Fancy Bear, Sofacy",
    "description": "Russian state-sponsored APT",
    "country_origin": "Russia",
    "primary_targets": "Government, Defense",
    "tactics": "Reconnaissance, Execution",
    "techniques": "T1087, T1059",
    "first_seen": "2007-01-15T00:00:00",
    "last_seen": "2024-01-10T00:00:00",
    "events_count": 5,
    "malware_count": 8,
    "phishing_count": 3,
    "iocs_count": 42
  }
]
```

### Get Specific APT
```json
GET /api/apts/1

{
  "id": 1,
  "name": "APT28",
  "aliases": "Fancy Bear, Sofacy",
  "description": "Russian state-sponsored APT",
  "country_origin": "Russia",
  "primary_targets": "Government, Defense",
  "tactics": "Reconnaissance, Execution",
  "techniques": "T1087, T1059",
  "first_seen": "2007-01-15",
  "last_seen": "2024-01-10",
  "events": [
    {"id": 1, "title": "APT28 Spear-phishing Campaign"}
  ],
  "malware": [
    {"id": 1, "name": "X-Agent"},
    {"id": 2, "name": "BlackEnergy"}
  ],
  "phishing": [
    {"id": 1, "subject": "Budget Proposal"}
  ],
  "iocs": [
    {
      "id": 1,
      "type": "hash",
      "value": "5d41402abc4b2a76b9719d911017c592"
    }
  ]
}
```

## Testing

To verify the implementation:

1. Start the TITAN application: `python main.py`
2. Navigate to `http://localhost:8080/apts`
3. Create a test APT
4. Verify it appears in the list
5. Edit and view the APT
6. Use API endpoints to verify JSON responses

## Code Changes Summary

### Files Modified:
1. `backend/db_models.py` - Added APT model and association tables
2. `backend/api.py` - Added APT endpoints and analytics
3. `frontend/templates/index.html` - Added APT card to dashboard

### Files Created:
1. `frontend/templates/apts/list.html` - APT list view
2. `frontend/templates/apts/detail.html` - APT detail view
3. `frontend/templates/apts/new.html` - APT creation form
4. `frontend/templates/apts/edit.html` - APT editing form

## Support

For issues or questions:
1. Check the database integrity with `/health` endpoint
2. Review application logs for error messages
3. Verify database migrations have been applied
4. Ensure all required fields are populated when creating APTs
