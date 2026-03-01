# HEARTBEAT.md — Finance Agent

<!-- 
  This file tells your agent what to check on each heartbeat cycle.
  Heartbeats fire every ~30 minutes. Not every check runs every time —
  use the schedule below to batch appropriately.
-->

## 🔄 Every Heartbeat (30 min)

- [ ] Check for urgent emails from banks, payment processors, or flagged vendors
- [ ] Review any pending approval requests (expenses, POs, transfers)

## 📅 Morning Check (First heartbeat after 8:00 AM)

- [ ] **Daily Cash Position:** Check bank balances across all accounts. Report total available cash.
- [ ] **AR Aging Snapshot:**
  - Current (0-30 days): report total
  - 31-60 days: list invoices, flag any > $5,000
  - 61-90 days: list all, recommend collection action
  - 90+ days: ⚠️ ALERT — list all with recommended escalation
- [ ] **AP Due Today/This Week:** List payments due, total amount, confirm sufficient cash
- [ ] **Bank Transaction Review:** Flag any unusual debits or unrecognized transactions

## 📊 Weekly (Monday morning)

- [ ] **P&L Summary:** Revenue, COGS, gross margin, operating expenses, net income — vs. budget and prior week
- [ ] **Cash Flow Forecast:** Updated 4-week rolling forecast
- [ ] **AR Collection Progress:** What was collected last week, what's still outstanding
- [ ] **AP Upcoming:** Major payments due this week, early-pay discount opportunities
- [ ] **Budget Variance Alert:** Flag any line items >10% over budget

## 📋 Monthly (1st business day)

- [ ] **Month-End Close Checklist:**
  - Bank reconciliations complete?
  - Credit card statements reconciled?
  - Accruals posted?
  - Depreciation entries posted?
  - Revenue recognition reviewed?
  - Intercompany entries cleared?
- [ ] **Monthly Financial Package:** P&L, Balance Sheet, Cash Flow Statement
- [ ] **KPI Dashboard:** Gross margin %, operating margin %, DSO, DPO, current ratio
- [ ] **Upcoming Tax Deadlines:** Flag anything due in the next 30 days

## 🚨 Alert Thresholds

<!-- Customize these for your business -->
- Cash below $__________: IMMEDIATE ALERT
- Single AR invoice > 60 days: FLAG
- AP payment > $__________: REQUIRE APPROVAL CONFIRMATION  
- Any unrecognized bank transaction: FLAG
- Budget variance > 15%: FLAG

## 💤 Quiet Hours

- After 8 PM: Only alert on cash emergencies or fraud indicators
- Weekends: Morning cash check only, skip routine reports
