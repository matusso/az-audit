# Azure Logging Compliance Audit

`azure-logging-compliance-audit.sh` is a read-only Bash + Azure CLI tool. It checks the Azure logging architecture against the *Audit Log Compliance Review* requirements (central LAW, 18–24 month hot retention, 5–6 year immutable archive, LAW → Event Hub → Cribl → SOC streaming). It covers every enabled subscription the signed-in identity can see in the current tenant.

```bash
chmod +x azure-logging-compliance-audit.sh
az login                      # or a service principal / managed identity
./azure-logging-compliance-audit.sh
```

---

## Part 1 — Design

### Execution model

```text
check_dependencies → init_output → get_tenant → get_subscriptions
  └─ per subscription (sequential; requests inside run in a bounded job pool, MAX_PARALLEL)
       inventory_resources            Azure Resource Graph (ARM /resources fallback), secrets redacted
       audit_subscription_activity_logs
       audit_diagnostic_settings      categories discovered per (type,kind,sku), cached; then settings per resource
       audit_log_analytics            workspace, /tables, Usage metadata query, /dataExports
       audit_event_hubs               namespace, network rules, hubs, consumer groups, auth-rule metadata, metrics
       audit_application_insights / audit_postgresql / audit_mysql / audit_sql / audit_databricks
  audit_entra                         tenant-level microsoft.aadiam diagnostic settings
  ensure_referenced_eventhubs         export destinations outside the inventoried subscriptions
  audit_storage / audit_worm          every storage account referenced by any log flow + name matches
  audit_rbac                          LAW, security EH, archive storage and their resource groups
  verify_cribl                        optional, only when CRIBL_API_URL + CRIBL_API_TOKEN are set
  correlate                           cross-hop controls (LAW→EH→Cribl, per-flow WORM, Entra, DB, UWWB)
  generate_summary                    CSV / JSON / Markdown
```

* **Evidence first, verdict second.** Each API response becomes a normalized record (`raw/records/*.jsonl`). Controls are then evaluated in jq, which keeps the logic deterministic and lets it be re-run offline.
* **Read-only guard.** `az()` is shadowed by a wrapper that allows only `az version`, `az account show|list`, `az cloud show`, `az rest --method get`, and `POST` to exactly two read-only query endpoints: Resource Graph, and the Log Analytics query API for `Usage` metadata. Anything else is blocked, including `listKeys`, SAS, connection-string, `publishingcredentials` and `/secrets` URLs on any method.
* **Secrets.** Keys are never requested. Every raw response is redacted recursively before it is written (for example App Insights `ConnectionString`/`InstrumentationKey`, and any value containing `sig=`, `AccountKey=` or `SharedAccessKey=`). The optional Cribl token goes to curl on stdin and never appears in argv, logs or files.
* **Resilience.** Transient errors (429, 5xx, timeouts, connection resets) are retried with exponential backoff and jitter (2/4/8/16/32 s, `MAX_RETRIES`). 403, 404, unsupported, API-version and bad-request errors are classified separately. API-version errors fall back to the next listed version. `nextLink` / `@odata.nextLink` / `$skipToken` paging is followed with loop detection. An incomplete page chain is reported as an error and never silently truncated. A failure on one resource only affects that resource.
* **Parallelism** is bash-3.2 compatible and bounded by `MAX_PARALLEL`. Each job writes to its own shard file, so output is never interleaved. `--no-parallel` runs everything sequentially.
* **Status semantics.** 403 → `NOT_VERIFIABLE`, never `FAIL`. Domain roll-ups rank FAIL > ERROR > WARNING > NOT_VERIFIABLE > PASS, so a domain is PASS only when nothing in it was unverifiable.

### Important Azure implementation facts used

| Topic | How the tool handles it |
|---|---|
| Diagnostic categories differ per type/SKU | Discovered with `diagnosticSettingsCategories` and never hard-coded. `categoryGroup` (`allLogs`, `audit`) entries are expanded to concrete categories. |
| "Required" categories | The `audit` category group plus `REQUIRED_CATEGORY_REGEX`. Types without an audit group fall back to all categories, and gaps there are reported as WARNING, not FAIL. |
| Storage diagnostics | Logs are on `blobServices/fileServices/queueServices/tableServices/default`, not on the account itself. All four are audited. |
| AzureDiagnostics vs resource-specific | `logAnalyticsDestinationType != Dedicated` means legacy mode. This is a LOW governance finding, and only for types known to support resource-specific tables. |
| LAW table retention | `/tables` gives per-table `retentionInDays`, `…AsDefault`, `totalRetentionInDays` and `plan`. Workspace retention is never assumed when a table overrides it. Basic/Auxiliary plans do not meet the hot-retention requirement. |
| Which tables have data | The `Usage` table (metadata only, bounded lookback). The table content itself is never read. |
| Data Export eligibility | Microsoft publishes the supported-table list only in documentation. Eligibility is heuristic unless `EXPORT_SUPPORTED_TABLES_FILE` is supplied, so unconfirmed gaps are WARNING, not FAIL. |
| Export with no `eventHubName` | Azure creates one hub per table (`am-<table>`). Delivery is checked on those hubs. |
| EH firewall | LAW Data Export needs *Allow trusted Microsoft services* when the namespace is firewalled or private, otherwise it is FAIL. |
| WORM | Evaluated per container: container policy → account default version-level policy → legal hold. Only `Locked` with period ≥ 1825 days passes. `allowProtectedAppendWrites` or versioning on their own never pass. |
| WORM per log flow | Resource logs go to `insights-logs-<category>`, Activity Log to `insights-activity-logs`. The verdict uses the container the flow actually writes to. |
| SQL auditing | `auditingSettings/default` plus the `master` database diagnostic setting for `SQLSecurityAuditEvents`. Activity Log is never treated as database auditing. |
| PostgreSQL | `shared_preload_libraries` contains `pgaudit`, `pgaudit.log` classes, connection logging, and `pgaudit.log_parameter` (payload risk). |
| RBAC | `roleAssignments?$filter=atScope()` returns direct and inherited assignments, and PIM eligibility instances are included. Role class is derived from role-definition permissions (Admin/Write/DataWrite/Read). Users are never resolved to names. |

---

## Part 2 — Script

See [`azure-logging-compliance-audit.sh`](azure-logging-compliance-audit.sh). Policy configuration is at the top of the file, and every value can be overridden with an environment variable.

Offline regression test (mock `az`, no Azure access): `./tests/run-mock-test.sh`.

---

## Part 3 — Compliance Matrix

| Control | Requirement | Azure evidence | PASS criteria | Failure criteria |
|---|---|---|---|---|
| SUB-001 | Subscription auditable | ARG / ARM resource list | Inventory succeeded | NOT_VERIFIABLE on 403 / missing |
| LOG-001 | Diagnostic settings present | `{id}/providers/Microsoft.Insights/diagnosticSettings` | ≥1 setting with an enabled log category | FAIL: none, or metrics-only (CRITICAL for prod + critical types) |
| LOG-002 | Required categories enabled | categories (+groups) vs enabled (expanded) | All required categories enabled | FAIL on missing audit-group categories. WARNING when the type has no audit group |
| LOG-003 | Central LAW destination | setting `workspaceId` per category | All required categories reach a LAW (matching `CENTRAL_LAW_REGEX` if set) | FAIL: nothing reaches a LAW. WARNING: partial |
| LOG-004 | Archive destination | setting `storageAccountId` | Required categories to Storage | WARNING (`RESOURCE_ARCHIVE_POLICY=warn`) / FAIL (`require`) |
| LOG-005 | Archive is locked WORM | `insights-logs-<category>` container policy | Locked ≥ 1825 d | FAIL: none / unlocked / too short. NOT_VERIFIABLE if unreadable |
| LOG-006 | All categories enabled | categories vs enabled | allLogs coverage | WARNING (LOW) |
| LOG-007 | Direct EH streaming (optional) | `eventHubAuthorizationRuleId` | Only if `RESOURCE_EVENTHUB_POLICY=warn` | WARNING (LOW) |
| LOGCAT-001/002/003 | Minimize AzureDiagnostics | `logAnalyticsDestinationType`, Usage, bounded summary | Resource-specific mode / no AzureDiagnostics ingestion | WARNING (LOW, governance) |
| LAW-001 | Workspace retention ≥ 548 d | workspace `retentionInDays` | ≥ `HOT_RETENTION_MIN_DAYS` | FAIL (MEDIUM) |
| LAW-002 | Table retention | `/tables` + Usage | Security/ops ≥ 548 d (Analytics plan); debug ≤ 30 d | FAIL (MEDIUM, debug LOW). NOT_VERIFIABLE if tables/activity unknown |
| LAW-003 | Data Export to EH | `/dataExports` | Enabled rule with EventHub destination | FAIL (HIGH): none / disabled / storage-only |
| LAW-004 | Export coverage | `MISSING = (ACTIVE ∩ EXPORTABLE) − EXPORTED` | Empty set | FAIL (confirmed eligible) / WARNING (eligibility unconfirmed) / NOT_VERIFIABLE |
| LAW-005 | Unsupported active tables | `ACTIVE − EXPORTABLE` | Empty | WARNING |
| LAW-006/007/008 | Daily cap, network/local auth, tier | workspace properties | No cap; private; local auth off; current tier | WARNING / FAIL (Free tier) |
| EH-001 | Security EH exists | namespaces/hubs vs `EXPECTED_EVENTHUB_REGEX` | Match found | FAIL (HIGH) |
| EH-002 | LAW → EH path | export rule → namespace, hub, network rule set | Destination exists, reachable (trusted services), matches naming | FAIL: missing destination/hub, firewall blocks. WARNING: naming/tier |
| EH-003 | EH network reviewed | `networkRuleSets/default`, private endpoints | Deny/private | WARNING |
| EH-004 | Downstream Cribl | consumer groups, OutgoingMessages, optional Cribl API | Cribl input for namespace + consumption observed | NOT_VERIFIABLE by default. WARNING when nothing is consumed |
| EH-005 | Azure-side delivery | IncomingMessages on target hubs | > 0 in lookback | WARNING (HIGH): 0 messages / hubs absent |
| EH-006/007 | TLS, local auth, retention/capacity | namespace/hub properties | TLS ≥ 1.2, SAS disabled, retention ≥ min | WARNING |
| ARC-001 | Archive storage configured | all log flows' storage references | ≥1 referenced archive (WORM-compliant) | FAIL (CRITICAL) when none |
| ARC-002 | Blob versioning | `blobServices/default` | Enabled (N/A for HNS) | WARNING |
| ARC-003 | Soft delete | blob + container soft delete | Both enabled | WARNING |
| ARC-004 | Immutability enabled | containers + account version-level policy | Some immutability on all evaluated log containers | FAIL (CRITICAL if referenced), WARNING if name-matched only |
| ARC-005 | Immutability LOCKED | policy `state` | Locked | FAIL (HIGH) Unlocked. WARNING legal hold only |
| ARC-006 | Retention ≥ 1825 d | `immutabilityPeriodSinceCreationInDays` | ≥ min | FAIL (MEDIUM) |
| ARC-007 | Retention ≥ 2190 d | same | ≥ target | WARNING (LOW) |
| ARC-008 | Lifecycle not deleting early | `managementPolicies/default` | No delete < 1825 d | WARNING |
| ARC-009/010/011/012 | TLS/HTTPS/network, change feed, append writes, shared key/public access | account + blob service | Hardened | WARNING |
| ACT-001 | Activity Log → LAW | subscription diagnostic settings | Administrative, Security, Policy → LAW | FAIL (CRITICAL when no setting at all, else HIGH) |
| ACT-002 | Activity Log → WORM | `insights-activity-logs` container | Locked ≥ 1825 d | FAIL (HIGH) |
| ACT-003 | Activity Log → EH | direct EH or LAW export of `AzureActivity` | Either path | FAIL (MEDIUM) |
| ACT-004 | All expected categories | subscription settings | All 8 categories | WARNING (LOW) |
| DB-001 | Database auditing | SQL `auditingSettings`, PG `pgaudit`, MySQL `audit_log_enabled` | Enabled | FAIL (HIGH). SQL MI: NOT_VERIFIABLE (T-SQL) |
| DB-002 | Audit logs to LAW | SQL master `SQLSecurityAuditEvents`, PG `PostgreSQLLogs`, MySQL `MySqlAuditLogs` | Category → LAW | FAIL (HIGH) |
| DB-003 | Audit archive / retention | storage target, retentionDays | Archive present, retention ≥ min or unlimited | WARNING / FAIL |
| DB-004/005 | Audit quality, DevOps audit | action groups, pgaudit classes, `log_parameter` | Auth + change groups; no parameter logging | WARNING |
| ENTRA-001…006 | Entra Audit/SignIn/NonInteractive/SP/MI/Provisioning | `microsoft.aadiam/diagnosticSettings`, fallback: Usage ingestion | Category → LAW (or ingestion observed) | FAIL if readable and missing. NOT_VERIFIABLE on 403 without ingestion evidence. N/A if category not offered |
| ENTRA-007 | Risk logs | same (P2 licensing) | Available categories exported | WARNING / N/A |
| ENTRA-008 | Entra archive + streaming | storage WORM + EH/LAW export | Both | WARNING / FAIL |
| DBX-001 | Databricks Premium | SKU | premium | FAIL (HIGH) |
| DBX-002/003 | Unity Catalog / access categories → LAW | discovered categories | Enabled to LAW | FAIL (MEDIUM). NOT_VERIFIABLE if category not offered |
| DBX-004/005 | Verbose audit, system tables, lineage | none in ARM | — | Always NOT_VERIFIABLE (data plane) |
| APP-001 | Workspace-based App Insights | `WorkspaceResourceId`, `IngestionMode` | LogAnalytics | FAIL (MEDIUM, classic) |
| APP-002 | App telemetry → EH | workspace export includes `AppRequests` | Exported | FAIL (MEDIUM) |
| APP-003 | App Insights local auth | `DisableLocalAuth` | true | WARNING (LOW) |
| UWWB-001 | CRUD audit evidence | custom tables, DCR/DCE, components | Never PASS | NOT_VERIFIABLE_FROM_AZURE_CONTROL_PLANE |
| UWWB-002 | No payload fields | custom table schema columns | No payload-like columns | WARNING |
| RBAC-001 | Read-only access model | role assignments (direct, inherited, PIM) | No non-allow-listed write/admin | WARNING (HIGH for direct admin/user write) |
| RBAC-002 | Reader groups read-only | group names vs `EXPECTED_READER_GROUPS_REGEX` | Only Read/DataRead roles | FAIL (HIGH) |
| RBAC-003 | Reader groups present on LAW | same | ≥1 expected group with reader role | WARNING / NOT_VERIFIABLE |

Regulatory mapping: logging controls provide *technical control evidence supporting* DORA Art. 12 (logging; see RTS (EU) 2024/1774 Art. 12) and ISO/IEC 27001:2022 A.8.15 / A.5.28. RBAC controls map to A.5.15 / A.8.2. No single setting establishes regulatory compliance.

---

## Part 4 — Known Limitations

Azure alone cannot prove the following. The tool reports them as `NOT_VERIFIABLE` or lists them under *Audit Coverage Limitations* in `summary.md`:

* **Cribl ingestion.** Azure can show that an Event Hub receives messages (IncomingMessages) and that *something* consumes them (OutgoingMessages, consumer groups). It cannot show that Cribl processed them or that Elasticsearch/SOC indexed them. `END_TO_END_DELIVERY_VERIFIED` is never claimed. The optional Cribl API check only confirms an input configured for the namespace.
* **Application CRUD semantics (UWWB).** Table, DCR or App Insights names and schemas are only hints. Whether CREATE/UPDATE/DELETE events are complete and payload-free is application behaviour.
* **Databricks data plane.** Unity Catalog system tables (`system.access.audit`, lineage), verbose audit logs and data-access event detail need Databricks account/workspace APIs.
* **RBAC visibility.** Resources or scopes the identity cannot read produce 403. These are counted, listed in `errors.csv`, and surfaced as `NOT_VERIFIABLE`. Effective permissions (deny assignments, nested groups, ABAC conditions, PIM activation) are not computed.
* **Entra tenant settings** need Entra roles (e.g. Security Reader / Global Reader). Without them the tool falls back to LAW ingestion evidence (`SigninLogs`, `AuditLogs`, …) and otherwise reports NOT_VERIFIABLE.
* **Data Export eligibility.** There is no API for the supported-table list. Supply `EXPORT_SUPPORTED_TABLES_FILE` (one table name per line, copied from Microsoft docs) for authoritative LAW-004 results.
* **Table activity** comes from the `Usage` table (needs Log Analytics data-read). Free tables missing from `Usage` can look inactive.
* **Blob-level WORM** (version-level policies on individual blobs) and per-database `CREATE EXTENSION pgaudit` are data-plane state.
* **SQL Managed Instance** server audits are T-SQL objects. Only the `SQLSecurityAuditEvents` diagnostic path is checked.
* **Cross-tenant subscriptions** are listed but skipped, because `az rest` tokens for tenant-scope calls are issued for the current tenant.
* **Resource Graph** can lag ARM by minutes. Resources deleted during the run are reported as NOT_VERIFIABLE with the 404 recorded.
* The per-(type, kind, SKU) category cache assumes resources of the same type/kind/SKU expose the same categories. A cache miss or failure falls back to a per-resource query.

---

## Part 5 — Usage

```bash
# Every enabled subscription in the current tenant
./azure-logging-compliance-audit.sh

# One subscription
./azure-logging-compliance-audit.sh --subscription xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Higher concurrency, explicit security Event Hub convention
MAX_PARALLEL=10 EXPECTED_EVENTHUB_REGEX='eh-vigre-sec-.*' ./azure-logging-compliance-audit.sh

# CI gate: exit 1 when any HIGH/CRITICAL FAIL exists; no colours
NO_COLOR=1 ./azure-logging-compliance-audit.sh --fail-on high --output-dir "$BUILD_DIR/audit"

# Stricter archive policy, central workspace naming, authoritative export table list
RESOURCE_ARCHIVE_POLICY=require CENTRAL_LAW_REGEX='^law-sec-' \
EXPORT_SUPPORTED_TABLES_FILE=./export-supported-tables.txt ./azure-logging-compliance-audit.sh

# Exclude sandbox subscriptions, skip RBAC, sequential
./azure-logging-compliance-audit.sh --exclude-subscription '(sandbox|playground)' --skip-rbac --no-parallel

# Optional Cribl verification (token read from env, never printed)
CRIBL_API_URL='https://cribl.example.internal:9000' CRIBL_WORKER_GROUP=default \
CRIBL_API_TOKEN="$(cat /run/secrets/cribl_token)" ./azure-logging-compliance-audit.sh
```

Options: `--subscription <id>` (repeatable), `--exclude-subscription <regex>`, `--output-dir <dir>`, `--no-parallel`, `--max-parallel <n>`, `--skip-rbac`, `--skip-table-analysis`, `--skip-data-queries`, `--skip-entra`, `--no-raw`, `--fail-on none|error|fail|high|critical`, `--verbose`, `--debug`, `--help`.

Exit codes: `0` completed · `1` `--fail-on` gate triggered · `3` prerequisites/authentication · `130` interrupted (partial reports are still written and marked).

### Output

```text
audit-output/<UTC timestamp>/
  summary.md  summary.json  findings.csv  resources.csv  diagnostic-settings.csv
  law.csv  law-tables.csv  law-data-exports.csv  event-hubs.csv  storage.csv  worm-policies.csv
  rbac.csv  activity-log.csv  application-insights.csv  databases.csv  databricks.csv  errors.csv
  audit.log
  raw/            redacted ARM responses referenced by findings' evidenceFile
  raw/records/    normalized evidence records (JSONL) used for evaluation
```

CSV files follow RFC 4180 (quoted, CRLF, embedded quotes doubled). Cells starting with `= + @` are prefixed with `'` to prevent spreadsheet formula injection.

### Minimum permissions

`Reader` on the subscriptions, `Log Analytics Reader` on workspaces (for the `Usage` metadata query), and optionally an Entra `Security Reader`/`Global Reader` role for tenant diagnostic settings plus Graph `Group.Read.All`-equivalent read access for group names. Missing permissions produce NOT_VERIFIABLE, never FAIL.
