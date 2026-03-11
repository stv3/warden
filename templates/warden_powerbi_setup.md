# Warden — Power BI Setup Guide

Connect Power BI to your Warden instance to build live vulnerability management dashboards.

---

## 1. Connect to Warden Data

### Option A: Live Web API (Recommended for up-to-date data)

1. Open Power BI Desktop
2. **Get Data → Web**
3. Set the URL to: `https://your-warden-host/api/export/tableau/findings.csv`
4. Under **Advanced**, add a Header:
   - Key: `Authorization`
   - Value: `Bearer <your_warden_token>`
5. Click **OK → Transform Data**

To get your token, run:
```bash
curl -X POST https://your-warden-host/auth/token \
  -F "username=admin" \
  -F "password=your_password" | jq -r .access_token
```

### Option B: CSV File Import (Offline / Scheduled)

1. Export findings from Warden: **Settings → Export → Download findings.csv**
2. Power BI Desktop → **Get Data → Text/CSV**
3. Select the downloaded `warden-findings.csv`

---

## 2. Power Query M — Data Transformations

Paste this into **Advanced Editor** after connecting to the CSV source:

```m
let
    // Load source (adjust path or URL as needed)
    Source = Csv.Document(
        File.Contents("C:\path\to\warden-findings.csv"),
        [Delimiter=",", Columns=22, Encoding=65001, QuoteStyle=QuoteStyle.None]
    ),
    PromotedHeaders = Table.PromoteHeaders(Source, [PromoteAllScalars=true]),

    // Type conversions
    TypedTable = Table.TransformColumnTypes(PromotedHeaders, {
        {"risk_score",      type number},
        {"cvss_score",      type number},
        {"epss_score",      type number},
        {"asset_criticality", type number},
        {"in_kev",          type logical},
        {"first_seen",      type datetime},
        {"last_seen",       type datetime},
        {"resolved_at",     type datetime},
        {"sla_due_date",    type date},
        {"kev_due_date",    type date}
    }),

    // Calculated: Days Open
    WithDaysOpen = Table.AddColumn(TypedTable, "Days Open", each
        if [resolved_at] <> null
        then Duration.Days([resolved_at] - [first_seen])
        else Duration.Days(DateTime.LocalNow() - [first_seen]),
        type number
    ),

    // Calculated: Risk Band
    WithRiskBand = Table.AddColumn(WithDaysOpen, "Risk Band", each
        if [risk_score] >= 80 then "Critical Risk"
        else if [risk_score] >= 60 then "High Risk"
        else if [risk_score] >= 40 then "Medium Risk"
        else if [risk_score] >= 20 then "Low Risk"
        else "Informational",
        type text
    ),

    // Calculated: SLA Status
    WithSLAStatus = Table.AddColumn(WithRiskBand, "SLA Status", each
        let today = Date.From(DateTime.LocalNow())
        in
        if [sla_due_date] = null then "No SLA"
        else if [sla_due_date] < today and [status] <> "resolved" then "Overdue"
        else if Duration.Days([sla_due_date] - today) <= 7 then "Due This Week"
        else "On Track",
        type text
    ),

    // Calculated: Age Category
    WithAgeCategory = Table.AddColumn(WithSLAStatus, "Age Category", each
        if [Days Open] <= 7 then "0-7 days"
        else if [Days Open] <= 30 then "8-30 days"
        else if [Days Open] <= 90 then "31-90 days"
        else if [Days Open] <= 180 then "91-180 days"
        else "180+ days",
        type text
    ),

    // Calculated: Is Active (open or in_progress)
    WithIsActive = Table.AddColumn(WithAgeCategory, "Is Active", each
        [status] = "open" or [status] = "in_progress",
        type logical
    ),

    // Calculated: Severity Order (for sorting)
    WithSeverityOrder = Table.AddColumn(WithIsActive, "Severity Order", each
        if [severity] = "critical" then 1
        else if [severity] = "high" then 2
        else if [severity] = "medium" then 3
        else if [severity] = "low" then 4
        else 5,
        type number
    ),

    // Calculated: KEV Urgency
    WithKEVUrgency = Table.AddColumn(WithSeverityOrder, "KEV Urgency", each
        let today = Date.From(DateTime.LocalNow())
        in
        if [in_kev] = true and [kev_due_date] <> null and [kev_due_date] < today then "OVERDUE - KEV"
        else if [in_kev] = true and [kev_due_date] <> null and Duration.Days([kev_due_date] - today) <= 7 then "Due This Week - KEV"
        else if [in_kev] = true and [kev_due_date] <> null and Duration.Days([kev_due_date] - today) <= 30 then "Due This Month - KEV"
        else if [in_kev] = true then "KEV - No Due Date"
        else "Not in KEV",
        type text
    )

in
    WithKEVUrgency
```

---

## 3. DAX Measures

Create these measures in your **Findings** table:

```dax
-- Total Active Findings
Total Active Findings =
CALCULATE(COUNTROWS(Findings), Findings[Is Active] = TRUE())

-- Critical Active Findings
Critical Findings =
CALCULATE(COUNTROWS(Findings), Findings[severity] = "critical", Findings[Is Active] = TRUE())

-- KEV Findings
KEV Findings =
CALCULATE(COUNTROWS(Findings), Findings[in_kev] = TRUE(), Findings[Is Active] = TRUE())

-- KEV Overdue
KEV Overdue =
CALCULATE(COUNTROWS(Findings), Findings[KEV Urgency] = "OVERDUE - KEV")

-- SLA Compliance Rate (%)
SLA Compliance Rate =
DIVIDE(
    CALCULATE(COUNTROWS(Findings), Findings[SLA Status] = "On Track", Findings[Is Active] = TRUE()),
    CALCULATE(COUNTROWS(Findings), Findings[SLA Status] <> "No SLA", Findings[Is Active] = TRUE()),
    0
) * 100

-- Average Risk Score (Active)
Avg Risk Score =
CALCULATE(AVERAGE(Findings[risk_score]), Findings[Is Active] = TRUE())

-- Average Days Open
Avg Days Open =
CALCULATE(AVERAGE(Findings[Days Open]), Findings[Is Active] = TRUE())

-- MTTR (Mean Time to Resolve) - days
MTTR =
CALCULATE(AVERAGE(Findings[Days Open]), Findings[status] = "resolved")

-- % Change in Active Findings (Month over Month)
MoM Change % =
VAR CurrentMonth = CALCULATE(COUNTROWS(Findings), Findings[Is Active] = TRUE(),
    MONTH(Findings[first_seen]) = MONTH(TODAY()),
    YEAR(Findings[first_seen]) = YEAR(TODAY()))
VAR PrevMonth = CALCULATE(COUNTROWS(Findings), Findings[Is Active] = TRUE(),
    MONTH(Findings[first_seen]) = MONTH(EDATE(TODAY(), -1)),
    YEAR(Findings[first_seen]) = YEAR(EDATE(TODAY(), -1)))
RETURN DIVIDE(CurrentMonth - PrevMonth, PrevMonth, 0) * 100

-- Findings by Severity Label (for KPI cards)
Critical Count Label =
"CRITICAL: " & FORMAT([Critical Findings], "#,0")
```

---

## 4. Recommended Visuals & Layout

### Page 1: Executive Overview

| Visual | Type | Fields |
|--------|------|--------|
| Total Active Findings | KPI Card | `Total Active Findings` |
| KEV Overdue | KPI Card | `KEV Overdue` |
| SLA Compliance | KPI Gauge | `SLA Compliance Rate` (target: 95%) |
| Avg Risk Score | KPI Card | `Avg Risk Score` |
| Severity Distribution | Donut Chart | Legend: `severity` · Values: Count · Sort: `Severity Order` |
| KEV Risk Matrix | Stacked Bar | Axis: `KEV Urgency` · Values: Count · Legend: `severity` |
| Environment Exposure | Stacked Bar | Axis: `asset_environment` · Values: Count · Legend: `severity` |
| SLA Heatmap | Matrix | Rows: `asset_environment` · Cols: `severity` · Values: `SLA Status` count |

**Slicers:** `asset_environment`, `severity`, `status`, `finding_type`

---

### Page 2: Asset & Operations

| Visual | Type | Fields |
|--------|------|--------|
| Top 20 Assets at Risk | Horizontal Bar | Axis: `asset_name` · Values: `Avg Risk Score` · Color: `severity` |
| Findings by Type | Bar Chart | Axis: `finding_type` · Values: Count · Color: `Risk Band` |
| Age Distribution | Bar Chart | Axis: `Age Category` · Values: Count · Color: `severity` |
| Owner Accountability | Horizontal Bar | Axis: `owner` · Values: Count · Color: `SLA Status` |
| MTTR by Severity | Bar Chart | Axis: `severity` · Values: `MTTR` |

**Slicers:** `owner`, `finding_type`, `asset_environment`

---

### Page 3: KEV & Compliance

| Visual | Type | Fields |
|--------|------|--------|
| KEV Urgency Breakdown | Stacked Bar | Axis: `KEV Urgency` · Values: Count · Color: `severity` |
| KEV Due Date Timeline | Timeline / Line | Axis: `kev_due_date` · Values: Count |
| SLA Status by Severity | Matrix | Rows: `severity` · Cols: `SLA Status` · Values: Count |
| Findings Over Time | Area Chart | Axis: `first_seen` (Month) · Values: Count · Color: `severity` |
| Risk Score Distribution | Histogram | Values: `risk_score` (bin size: 10) |

---

## 5. Scheduled Refresh

### Power BI Service (Cloud)

1. Publish your `.pbix` to Power BI Service
2. Go to **Dataset Settings → Scheduled Refresh**
3. Set to refresh **Daily** (or multiple times per day)
4. If using Web API source, configure **Data Source Credentials** with the Bearer token

### On-Premises Gateway

If Warden is hosted internally:
1. Install **Power BI On-premises Data Gateway**
2. Register your Warden server as a data source
3. Map the gateway in Dataset Settings

---

## 6. Row-Level Security (Optional)

To restrict views by owner or environment, create an RLS role:

```dax
-- RLS: Owner View (users see only their own findings)
[owner] = USERPRINCIPALNAME()

-- RLS: Production Only
[asset_environment] = "production"
```

Apply via **Modeling → Manage Roles** in Power BI Desktop.

---

## 7. File Reference

- Warden CSV Export: `GET /api/export/tableau/findings.csv`
- Warden KEV Summary: `GET /api/export/tableau/kev-summary.csv`
- Auth token: `POST /auth/token` (form: `username`, `password`)
- Power BI template file: Save your configured `.pbix` and share with your team
