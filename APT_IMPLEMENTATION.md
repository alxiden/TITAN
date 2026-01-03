# TITAN APT Feature - Implementation Summary

## What Has Been Implemented

### 1. Database Model (`backend/db_models.py`)

**New APT Model:**
```python
class APT(Base):
    __tablename__ = "apts"
    - id (Primary Key)
    - name (Unique)
    - aliases
    - description
    - country_origin
    - primary_targets
    - tactics
    - techniques
    - first_seen
    - last_seen
    - created_at
    - updated_at
```

**Association Tables (Many-to-Many):**
- `apt_events` - Links APTs to Events
- `apt_malware` - Links APTs to Malware
- `apt_phishing` - Links APTs to Phishing
- `apt_iocs` - Links APTs to IOCs

**Updated Models:**
- Event: Added `apts` relationship
- Malware: Added `apts` relationship
- Phish: Added `apts` relationship
- IOC: Added `apts` relationship

### 2. API Endpoints (`backend/api.py`)

#### Web Routes (HTML)
```
GET  /apts                              - List all APTs
GET  /apts/{id}                         - View APT details
GET  /apts/new/form                     - Show creation form
POST /apts/new                          - Create new APT
GET  /apts/{id}/edit                    - Show edit form
POST /apts/{id}/edit                    - Update APT
POST /apts/{id}/delete                  - Delete APT
```

#### Linking/Unlinking Routes
```
POST /apts/{apt_id}/link/event/{event_id}      - Link APT to Event
POST /apts/{apt_id}/unlink/event/{event_id}    - Unlink APT from Event
POST /apts/{apt_id}/link/malware/{malware_id}  - Link APT to Malware
POST /apts/{apt_id}/unlink/malware/{malware_id}- Unlink APT from Malware
POST /apts/{apt_id}/link/phish/{phish_id}      - Link APT to Phishing
POST /apts/{apt_id}/unlink/phish/{phish_id}    - Unlink APT from Phishing
POST /apts/{apt_id}/link/ioc/{ioc_id}          - Link APT to IOC
POST /apts/{apt_id}/unlink/ioc/{ioc_id}        - Unlink APT from IOC
```

#### JSON API Routes
```
GET /api/apts                 - Get all APTs with counts
GET /api/apts/{id}           - Get APT details with linked entities
GET /api/charts/apts-top     - Get top APTs by activity
```

### 3. Web Templates

**Created Files:**
- `frontend/templates/apts/list.html` - APT list with search functionality
- `frontend/templates/apts/detail.html` - Detailed APT view with all relationships
- `frontend/templates/apts/new.html` - Form to create new APT
- `frontend/templates/apts/edit.html` - Form to edit APT

**Modified Files:**
- `frontend/templates/index.html` - Added APT card to dashboard

### 4. Dashboard Integration

- APT count displayed on homepage
- APT card links to `/apts` page
- APT count updated in real-time with other threat metrics

## How to Use

### Creating an APT

1. Navigate to **APTs** from the home dashboard
2. Click **+ Add APT** button
3. Fill in the APT details:
   - Name (required, must be unique)
   - Aliases (comma-separated)
   - Description
   - Country of Origin
   - Primary Targets (comma-separated)
   - MITRE ATT&CK Tactics (comma-separated)
   - MITRE ATT&CK Techniques (comma-separated)
   - First Seen date
   - Last Seen date
4. Click **Create APT**

### Linking APTs to Other Entities

#### Via Web Interface:

**From APT Detail Page:**
1. View an APT (click on its name in the list)
2. Scroll to the linked entities sections
3. Currently shows all linked items with unlink buttons
4. To link new items, use the API endpoints below

#### Via API/Forms:

**Link APT to Event:**
```bash
POST /apts/{apt_id}/link/event/{event_id}
```

**Link APT to Malware:**
```bash
POST /apts/{apt_id}/link/malware/{malware_id}
```

**Link APT to Phishing:**
```bash
POST /apts/{apt_id}/link/phish/{phish_id}
```

**Link APT to IOC:**
```bash
POST /apts/{apt_id}/link/ioc/{ioc_id}
```

### Viewing APT Details

1. Click on an APT name in the list
2. The detail page shows:
   - Basic APT information
   - All linked Events with their status/severity
   - All linked Malware with families and IOC counts
   - All linked Phishing campaigns
   - All linked IOCs with types and values
   - Quick unlink buttons for each relationship

## Data Relationships

```
┌─────────────────────────────────────┐
│           APT (Core)                │
├─────────────────────────────────────┤
│ - name (unique)                     │
│ - aliases                           │
│ - description                       │
│ - country_origin                    │
│ - primary_targets                   │
│ - tactics                           │
│ - techniques                        │
│ - first_seen / last_seen            │
└────────┬────────┬────────┬──────────┘
         │        │        │
    ┌────▼─┐  ┌──▼──┐  ┌──▼──┐  ┌──────┐
    │Events│  │Malw │  │Phish│  │IOCs  │
    └──────┘  └─────┘  └─────┘  └──────┘
```

## Database Changes Required

The following SQL will be created automatically when the app starts with the new models:

```sql
CREATE TABLE apts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name VARCHAR(256) NOT NULL UNIQUE,
  aliases TEXT,
  description TEXT,
  country_origin VARCHAR(128),
  primary_targets TEXT,
  tactics TEXT,
  techniques TEXT,
  first_seen DATETIME,
  last_seen DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE apt_events (
  apt_id INTEGER NOT NULL,
  event_id INTEGER NOT NULL,
  PRIMARY KEY (apt_id, event_id),
  FOREIGN KEY (apt_id) REFERENCES apts(id),
  FOREIGN KEY (event_id) REFERENCES events(id)
);

CREATE TABLE apt_malware (
  apt_id INTEGER NOT NULL,
  malware_id INTEGER NOT NULL,
  PRIMARY KEY (apt_id, malware_id),
  FOREIGN KEY (apt_id) REFERENCES apts(id),
  FOREIGN KEY (malware_id) REFERENCES malware(id)
);

CREATE TABLE apt_phishing (
  apt_id INTEGER NOT NULL,
  phish_id INTEGER NOT NULL,
  PRIMARY KEY (apt_id, phish_id),
  FOREIGN KEY (apt_id) REFERENCES apts(id),
  FOREIGN KEY (phish_id) REFERENCES phishing(id)
);

CREATE TABLE apt_iocs (
  apt_id INTEGER NOT NULL,
  ioc_id INTEGER NOT NULL,
  PRIMARY KEY (apt_id, ioc_id),
  FOREIGN KEY (apt_id) REFERENCES apts(id),
  FOREIGN KEY (ioc_id) REFERENCES iocs(id)
);
```

## Testing the Implementation

1. **Start the application:**
   ```bash
   python main.py
   ```

2. **Create a test APT:**
   ```
   Navigate to http://localhost:8080/apts
   Click "+ Add APT"
   Fill in details and create
   ```

3. **Test the API:**
   ```bash
   # Get all APTs
   curl http://localhost:8080/api/apts
   
   # Get specific APT
   curl http://localhost:8080/api/apts/1
   
   # Get top APTs
   curl "http://localhost:8080/api/charts/apts-top?days=30&top=10"
   ```

4. **Test linking (via Python/requests):**
   ```python
   import requests
   
   # Link APT 1 to Event 1
   requests.post('http://localhost:8080/apts/1/link/event/1')
   
   # Verify on APT detail page
   # http://localhost:8080/apts/1
   ```

## Future Enhancement Opportunities

1. **UI Enhancements:**
   - Quick-link dropdown on Event/Malware/Phishing detail pages
   - Bulk linking operations
   - APT search/filter in linking dialogs

2. **Analytics:**
   - APT activity timeline visualization
   - APT correlation matrix (which APTs target same sectors)
   - APT technique heat map (MITRE ATT&CK)

3. **Integration:**
   - Auto-detect APT from IOCs using threat feeds
   - Import APT data from external sources
   - Export APT profiles

4. **Advanced Features:**
   - Custom APT fields and attributes
   - APT confidence scoring
   - APT group aliases/variants
   - APT infrastructure mapping
   - Threat level assessment

## Notes

- **APT names are unique:** No duplicate APT names allowed
- **Cascade behavior:** Deleting an APT only removes relationships, not the linked entities
- **Session management:** All endpoints properly close database sessions
- **Date handling:** Dates can be entered as YYYY-MM-DD format
- **Text fields:** Comma-separated values are used for lists (tactics, techniques, targets, etc.)

## Files Modified Summary

| File | Changes |
|------|---------|
| `backend/db_models.py` | Added APT model, 4 association tables, updated existing models |
| `backend/api.py` | Added 14 new endpoints, updated db_counts function |
| `frontend/templates/index.html` | Added APT card to dashboard |
| `frontend/templates/apts/` | Created 4 new template files |

## Compatibility

- Maintains backward compatibility with existing TITAN functionality
- No breaking changes to existing APIs
- Existing data remains unchanged
- Database migrations handled automatically by SQLAlchemy ORM

## Next Steps

1. Restart the TITAN application to initialize the new tables
2. Navigate to the APTs section to start using the feature
3. Create APTs and begin linking them to your threat intelligence data
4. Monitor APT activity through the dashboard and detail pages
5. Use API endpoints for programmatic access and integration

For detailed API documentation and additional examples, see `APT_FEATURE_GUIDE.md`.
