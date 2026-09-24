#!/usr/bin/env bash
# =============================================================================
# azure-logging-compliance-audit.sh
#
# Read-only Azure audit-logging compliance review.
#
# Audits, across every enabled subscription visible to the signed-in Azure CLI
# identity (current tenant):
#   - Resource Diagnostic Settings (available vs. enabled categories, per destination)
#   - Log Analytics Workspaces (retention, table-level retention, Data Export)
#   - LAW -> Event Hub -> (Cribl) streaming path
#   - Immutable (WORM) archive storage (container / account / version-level policies)
#   - Subscription Activity Log export
#   - Entra ID diagnostic settings (tenant level, if permitted)
#   - PostgreSQL Flexible Server / MySQL Flexible Server / Azure SQL auditing
#   - Azure Databricks diagnostic categories
#   - Application Insights architecture (workspace-based vs. classic)
#   - UWWB application audit evidence (control-plane evidence only)
#   - RBAC on logging infrastructure
#
# SAFETY
#   The tool performs only GET requests against Azure Resource Manager / Microsoft
#   Graph, plus POST requests to exactly two read-only query endpoints (Azure
#   Resource Graph query, Log Analytics query API). Every `az` invocation passes
#   through a guard (az_guard) that blocks anything else. No keys, SAS tokens or
#   connection strings are ever requested (listKeys-style endpoints are blocked)
#   and raw evidence is redacted before it is written to disk.
#
# REQUIREMENTS
#   bash >= 3.2 (macOS default works), Azure CLI >= 2.40 (az rest), jq >= 1.6.
#   Optional: curl (only for optional Cribl API verification), timeout/gtimeout.
#
# EXIT CODES
#   0  audit completed (and --fail-on gate not triggered)
#   1  audit completed, --fail-on gate triggered
#   3  prerequisite / authentication failure
#   130 interrupted (partial reports are still written)
# =============================================================================

set -uo pipefail
IFS=$' \t\n'
umask 077

readonly TOOL_NAME="azure-logging-compliance-audit"
readonly TOOL_VERSION="1.0.0"

# =============================================================================
# POLICY CONFIGURATION (every value can be overridden via environment variable)
# All *_REGEX values are evaluated case-insensitively by jq (Oniguruma syntax).
# =============================================================================

# --- LAW hot retention -------------------------------------------------------
HOT_RETENTION_MIN_DAYS="${HOT_RETENTION_MIN_DAYS:-548}"      # 18 months
HOT_RETENTION_MAX_DAYS="${HOT_RETENTION_MAX_DAYS:-730}"      # 24 months
DEBUG_RETENTION_MAX_DAYS="${DEBUG_RETENTION_MAX_DAYS:-30}"
# Tables explicitly classified as debug/diagnostic (max DEBUG_RETENTION_MAX_DAYS).
DEBUG_TABLE_REGEX="${DEBUG_TABLE_REGEX:-(debug|verbose)}"
# Tables exempt from the hot-retention requirement (e.g. billing/usage tables).
HOT_RETENTION_EXEMPT_TABLE_REGEX="${HOT_RETENTION_EXEMPT_TABLE_REGEX:-^(Usage|Operation)$}"
# Security/audit tables evaluated even when table activity cannot be determined.
SECURITY_TABLE_REGEX="${SECURITY_TABLE_REGEX:-^(SigninLogs|AuditLogs|AAD.*|AzureActivity|AzureDiagnostics|SecurityEvent|SecurityAlert|SecurityIncident|Syslog|CommonSecurityLog|AZKVAuditLogs|StorageBlobLogs|StorageFileLogs|SQLSecurityAuditEvents|PGSQL.*|Databricks.*|AKSAudit.*|AZFW.*|AGW.*|MicrosoftGraphActivityLogs|App(Requests|Events|Exceptions)|.*_CL)$}"

# --- Long-term archive (immutable storage) --------------------------------------
ARCHIVE_RETENTION_MIN_DAYS="${ARCHIVE_RETENTION_MIN_DAYS:-1825}"      # 5 years
ARCHIVE_RETENTION_TARGET_DAYS="${ARCHIVE_RETENTION_TARGET_DAYS:-2190}" # 6 years
# Storage accounts treated as "apparently dedicated" to logging/archive even if
# no diagnostic setting references them.
ARCHIVE_STORAGE_REGEX="${ARCHIVE_STORAGE_REGEX:-(log|audit|archiv|worm|siem|sec)}"
# Containers considered log containers (insights-* = diagnostic settings,
# am-* = LAW data export). If none match, all containers are evaluated.
LOG_CONTAINER_REGEX="${LOG_CONTAINER_REGEX:-^(insights-|am-)|(log|audit|archiv)}"
# warn | require | off : is a Storage destination required on resource diagnostic settings?
RESOURCE_ARCHIVE_POLICY="${RESOURCE_ARCHIVE_POLICY:-warn}"

# --- Event Hub / Cribl ------------------------------------------------------------
EXPECTED_EVENTHUB_REGEX="${EXPECTED_EVENTHUB_REGEX:-eh-vigre-sec-.*}"  # matched against namespace OR hub name
EH_MIN_RETENTION_DAYS="${EH_MIN_RETENTION_DAYS:-1}"
EH_METRICS_LOOKBACK_HOURS="${EH_METRICS_LOOKBACK_HOURS:-24}"
CRIBL_CONSUMER_GROUP_REGEX="${CRIBL_CONSUMER_GROUP_REGEX:-cribl}"
# off | warn : should resources also stream directly to Event Hub (primary path is LAW export)?
RESOURCE_EVENTHUB_POLICY="${RESOURCE_EVENTHUB_POLICY:-off}"
# Optional Cribl API verification (never printed). Example: https://cribl.example.com:9000
CRIBL_API_URL="${CRIBL_API_URL:-}"
CRIBL_API_TOKEN="${CRIBL_API_TOKEN:-}"
CRIBL_WORKER_GROUP="${CRIBL_WORKER_GROUP:-}"

# --- Central LAW / production detection ----------------------------------------------
CENTRAL_LAW_REGEX="${CENTRAL_LAW_REGEX:-}"   # empty = any LAW counts as central
LAW_EXCLUDE_REGEX="${LAW_EXCLUDE_REGEX:-}"   # LAWs excluded from LAW -> EH requirements
PROD_REGEX="${PROD_REGEX:-(^|[^a-z0-9])(prod|prd|production|live)([^a-z0-9]|$)}"
CRITICAL_TYPES_REGEX="${CRITICAL_TYPES_REGEX:-^microsoft\\.(keyvault/vaults|sql/servers(/databases)?|sql/managedinstances|dbforpostgresql/flexibleservers|dbformysql/flexibleservers|databricks/workspaces|containerservice/managedclusters|network/azurefirewalls|network/applicationgateways|network/frontdoors|cdn/profiles|apimanagement/service|storage/storageaccounts/blobservices|eventhub/namespaces|web/sites|documentdb/databaseaccounts|operationalinsights/workspaces|recoveryservices/vaults|cognitiveservices/accounts)$}"

# --- Diagnostic category policy ---------------------------------------------------------
# audit : required = categories in the 'audit' category group (+ REQUIRED_CATEGORY_REGEX)
# all   : required = every available log category
REQUIRED_CATEGORIES_MODE="${REQUIRED_CATEGORIES_MODE:-audit}"
REQUIRED_CATEGORY_REGEX="${REQUIRED_CATEGORY_REGEX:-(audit|security|signin|authentication|accesslog|firewall|sqlsecurity|postgresqllogs|unitycatalog|accounts)}"
# Resource types known to support resource-specific ("Dedicated") LAW tables.
DEDICATED_CAPABLE_TYPES_REGEX="${DEDICATED_CAPABLE_TYPES_REGEX:-^microsoft\\.(datafactory/factories|recoveryservices/vaults|apimanagement/service|network/azurefirewalls|network/applicationgateways|devices/iothubs|eventhub/namespaces|servicebus/namespaces|containerservice/managedclusters|keyvault/vaults|dbforpostgresql/flexibleservers|databricks/workspaces)$}"
# Types that never expose Diagnostic Settings (saves API calls; reported as SKIPPED).
DIAG_SKIP_TYPES_REGEX="${DIAG_SKIP_TYPES_REGEX:-^microsoft\\.(compute/(disks|snapshots|images|sshpublickeys|restorepointcollections|availabilitysets|virtualmachines/extensions|galleries(/.*)?)|network/(networkwatchers(/.*)?|privatednszones/virtualnetworklinks|routetables|networkintentpolicies)|managedidentity/userassignedidentities|portal/dashboards|operationsmanagement/solutions|alertsmanagement/.*|insights/(actiongroups|metricalerts|activitylogalerts|workbooks|webtests)|web/connections|resources/.*)$}"
# Storage sub-services whose diagnostic settings are audited.
STORAGE_DIAG_SERVICES="${STORAGE_DIAG_SERVICES:-blob file queue table}"

# --- Activity Log / Entra -------------------------------------------------------------
ACTIVITY_REQUIRED_CATEGORIES="${ACTIVITY_REQUIRED_CATEGORIES:-Administrative Security Policy}"
ACTIVITY_EXPECTED_CATEGORIES="${ACTIVITY_EXPECTED_CATEGORIES:-Administrative Security ServiceHealth Alert Recommendation Policy Autoscale ResourceHealth}"

# --- LAW Data Export -----------------------------------------------------------------------
# Optional file with one table name per line (e.g. copied from Microsoft's
# "Log Analytics workspace data export - supported tables" documentation). When
# supplied, export eligibility becomes authoritative instead of heuristic.
EXPORT_SUPPORTED_TABLES_FILE="${EXPORT_SUPPORTED_TABLES_FILE:-}"
EXPORT_UNSUPPORTED_TABLE_REGEX="${EXPORT_UNSUPPORTED_TABLE_REGEX:-}"
EXPORT_UNSUPPORTED_PLANS="${EXPORT_UNSUPPORTED_PLANS:-Auxiliary}"
ENABLE_DATA_QUERIES="${ENABLE_DATA_QUERIES:-true}"      # LAW 'Usage' metadata queries
ACTIVE_TABLE_LOOKBACK_DAYS="${ACTIVE_TABLE_LOOKBACK_DAYS:-30}"
AZDIAG_QUERY="${AZDIAG_QUERY:-true}"                    # bounded AzureDiagnostics summary
AZDIAG_LOOKBACK_HOURS="${AZDIAG_LOOKBACK_HOURS:-24}"

# --- Databases ------------------------------------------------------------------------------
PGAUDIT_REQUIRED_CLASSES="${PGAUDIT_REQUIRED_CLASSES:-ddl write role}"
SQL_CHECK_DATABASE_AUDIT="${SQL_CHECK_DATABASE_AUDIT:-auto}"   # auto | always | never

# --- UWWB -------------------------------------------------------------------------------------
UWWB_REGEX="${UWWB_REGEX:-uwwb}"
UWWB_PAYLOAD_COLUMN_REGEX="${UWWB_PAYLOAD_COLUMN_REGEX:-(payload|body|request_?content|response_?content|rawdata|document|password|secret)}"

# --- RBAC ---------------------------------------------------------------------------------------
EXPECTED_READER_GROUPS_REGEX="${EXPECTED_READER_GROUPS_REGEX:-(dev|data|general.?reader|log.?reader)}"
ALLOWED_PRIVILEGED_PRINCIPALS_REGEX="${ALLOWED_PRIVILEGED_PRINCIPALS_REGEX:-}"
PRIVILEGED_ROLES="${PRIVILEGED_ROLES:-Owner|Contributor|User Access Administrator|Role Based Access Control Administrator|Log Analytics Contributor|Monitoring Contributor|Storage Account Contributor|Storage Blob Data Contributor|Storage Blob Data Owner|Azure Event Hubs Data Owner|Azure Event Hubs Data Sender}"
RESOLVE_PRINCIPAL_NAMES="${RESOLVE_PRINCIPAL_NAMES:-true}"   # groups and service principals only, never users

# --- Subscription scope ------------------------------------------------------------------------------
EXCLUDE_SUBSCRIPTIONS_REGEX="${EXCLUDE_SUBSCRIPTIONS_REGEX:-}"
MANAGEMENT_SUBSCRIPTIONS_REGEX="${MANAGEMENT_SUBSCRIPTIONS_REGEX:-}"
EXCLUDE_MANAGEMENT_SUBSCRIPTIONS="${EXCLUDE_MANAGEMENT_SUBSCRIPTIONS:-false}"

# --- Execution --------------------------------------------------------------------------------------
MAX_RETRIES="${MAX_RETRIES:-5}"
RETRY_BASE_DELAY="${RETRY_BASE_DELAY:-2}"
MAX_PARALLEL="${MAX_PARALLEL:-5}"
MAX_PAGES="${MAX_PAGES:-500}"
AZ_TIMEOUT_SECONDS="${AZ_TIMEOUT_SECONDS:-180}"
OUTPUT_DIR="${OUTPUT_DIR:-audit-output}"
SAVE_RAW="${SAVE_RAW:-true}"
FAIL_ON="${FAIL_ON:-none}"     # none | error | fail | high | critical
MD_MAX_FINDINGS="${MD_MAX_FINDINGS:-150}"
REMEDIATION_MAX_EXAMPLES="${REMEDIATION_MAX_EXAMPLES:-15}"
LA_QUERY_ENDPOINT="${LA_QUERY_ENDPOINT:-https://api.loganalytics.io}"

# --- API versions (explicit; fallbacks are tried only on API-version errors) -----------------------------
API_DIAG="${API_DIAG:-2021-05-01-preview}"                 # Microsoft.Insights/diagnosticSettings(+Categories)
API_ARG="${API_ARG:-2022-10-01}"                           # Microsoft.ResourceGraph/resources
API_RESOURCES="${API_RESOURCES:-2021-04-01}"               # ARM generic resource list (ARG fallback)
API_LAW="${API_LAW:-2022-10-01 2020-08-01}"                # workspaces + tables
API_LAW_EXPORT="${API_LAW_EXPORT:-2020-08-01}"             # workspaces/dataExports
API_EH="${API_EH:-2024-01-01 2021-11-01}"                  # Microsoft.EventHub
API_STORAGE="${API_STORAGE:-2023-05-01 2023-01-01 2022-09-01}"
API_SQL="${API_SQL:-2021-11-01}"
API_PG="${API_PG:-2022-12-01 2021-06-01}"
API_MYSQL="${API_MYSQL:-2023-12-30 2021-05-01}"
API_APPI="${API_APPI:-2020-02-02}"
API_DATABRICKS="${API_DATABRICKS:-2024-05-01 2023-02-01}"
API_AUTH="${API_AUTH:-2022-04-01}"                         # roleAssignments / roleDefinitions
API_PIM="${API_PIM:-2020-10-01}"                           # roleEligibilityScheduleInstances
API_AADIAM="${API_AADIAM:-2017-04-01}"                     # microsoft.aadiam/diagnosticSettings
API_AADIAM_CAT="${API_AADIAM_CAT:-2017-04-01-preview}"     # microsoft.aadiam/diagnosticSettingsCategories
API_METRICS="${API_METRICS:-2018-01-01}"                   # Microsoft.Insights/metrics

# =============================================================================
# RUNTIME STATE
# =============================================================================
OPT_SUBSCRIPTIONS=""
OPT_SKIP_RBAC=false
OPT_SKIP_TABLES=false
OPT_SKIP_ENTRA=false
VERBOSE=false
DEBUG=false
PARALLEL=true
INTERRUPTED=false

RC_OK=0; RC_ERROR=1; RC_FORBIDDEN=3; RC_NOTFOUND=4; RC_UNSUPPORTED=5; RC_APIVERSION=6
RC_BADREQUEST=7; RC_AUTH=8; RC_BLOCKED=97

AZ_BIN=""
TIMEOUT_BIN=""
ARM="https://management.azure.com"
ARM_LC="https://management.azure.com"
GRAPH="https://graph.microsoft.com"
RUN_TS=""
RUN_DIR=""
RAW_DIR=""
WORK=""
JQLIB_DIR=""
SHARD_DIR=""
LOG_FILE=""
TENANT_ID=""
JOB_SEQ=0
START_EPOCH="$(date +%s)"

# =============================================================================
# CLI
# =============================================================================
usage() {
  cat <<'EOF'
Usage: azure-logging-compliance-audit.sh [options]

Read-only audit of Azure logging architecture against the Audit Log Compliance
Review requirements. By default every enabled subscription of the current tenant
that is visible to the signed-in Azure CLI identity is audited.

Options:
  --subscription <id>           Audit only this subscription (repeatable)
  --exclude-subscription <re>   Exclude subscriptions whose id or name matches regex
  --output-dir <dir>            Output base directory (default: audit-output)
  --no-parallel                 Sequential execution (same as --max-parallel 1)
  --max-parallel <n>            Concurrent Azure requests (default: 5)
  --skip-rbac                   Do not audit role assignments
  --skip-table-analysis         Do not list LAW tables / table retention / export sets
  --skip-data-queries           Do not run LAW 'Usage' metadata queries
  --skip-entra                  Do not query tenant-level Entra diagnostic settings
  --no-raw                      Do not store redacted raw API evidence
  --fail-on <level>             none|error|fail|high|critical (exit 1 when triggered)
  --verbose                     Print PASS findings and extra progress
  --debug                       Print every Azure request (no secrets are ever printed)
  --version                     Print version
  --help                        This help

Environment: every policy value at the top of the script can be overridden, e.g.
  HOT_RETENTION_MIN_DAYS=548 ARCHIVE_RETENTION_MIN_DAYS=1825
  EXPECTED_EVENTHUB_REGEX='eh-vigre-sec-.*' MAX_PARALLEL=10 NO_COLOR=1
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --subscription) [ $# -ge 2 ] || { echo "--subscription requires a value" >&2; exit 3; }
                      OPT_SUBSCRIPTIONS="$OPT_SUBSCRIPTIONS $2"; shift 2 ;;
      --exclude-subscription) [ $# -ge 2 ] || { echo "--exclude-subscription requires a value" >&2; exit 3; }
                      EXCLUDE_SUBSCRIPTIONS_REGEX="$2"; shift 2 ;;
      --output-dir)   [ $# -ge 2 ] || { echo "--output-dir requires a value" >&2; exit 3; }
                      OUTPUT_DIR="$2"; shift 2 ;;
      --no-parallel)  PARALLEL=false; MAX_PARALLEL=1; shift ;;
      --max-parallel) [ $# -ge 2 ] || { echo "--max-parallel requires a value" >&2; exit 3; }
                      MAX_PARALLEL="$2"; shift 2 ;;
      --skip-rbac)    OPT_SKIP_RBAC=true; shift ;;
      --skip-table-analysis) OPT_SKIP_TABLES=true; shift ;;
      --skip-data-queries) ENABLE_DATA_QUERIES=false; AZDIAG_QUERY=false; shift ;;
      --skip-entra)   OPT_SKIP_ENTRA=true; shift ;;
      --no-raw)       SAVE_RAW=false; shift ;;
      --fail-on)      [ $# -ge 2 ] || { echo "--fail-on requires a value" >&2; exit 3; }
                      FAIL_ON="$2"; shift 2 ;;
      --verbose)      VERBOSE=true; shift ;;
      --debug)        DEBUG=true; VERBOSE=true; shift ;;
      --version)      echo "$TOOL_NAME $TOOL_VERSION"; exit 0 ;;
      -h|--help)      usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage >&2; exit 3 ;;
    esac
  done
  case "$MAX_PARALLEL" in ''|*[!0-9]*) echo "--max-parallel must be a positive integer" >&2; exit 3 ;; esac
  [ "$MAX_PARALLEL" -ge 1 ] || MAX_PARALLEL=1
  [ "$MAX_PARALLEL" -eq 1 ] && PARALLEL=false
  case "$FAIL_ON" in none|error|fail|high|critical) ;; *) echo "--fail-on must be none|error|fail|high|critical" >&2; exit 3 ;; esac
  case "$RESOURCE_ARCHIVE_POLICY" in warn|require|off) ;; *) echo "RESOURCE_ARCHIVE_POLICY must be warn|require|off" >&2; exit 3 ;; esac
  case "$REQUIRED_CATEGORIES_MODE" in audit|all) ;; *) echo "REQUIRED_CATEGORIES_MODE must be audit|all" >&2; exit 3 ;; esac
  local n
  for n in HOT_RETENTION_MIN_DAYS HOT_RETENTION_MAX_DAYS DEBUG_RETENTION_MAX_DAYS ARCHIVE_RETENTION_MIN_DAYS \
           ARCHIVE_RETENTION_TARGET_DAYS MAX_RETRIES RETRY_BASE_DELAY MAX_PAGES EH_MIN_RETENTION_DAYS \
           EH_METRICS_LOOKBACK_HOURS ACTIVE_TABLE_LOOKBACK_DAYS AZDIAG_LOOKBACK_HOURS AZ_TIMEOUT_SECONDS; do
    case "${!n}" in ''|*[!0-9]*) echo "$n must be a non-negative integer (got '${!n}')" >&2; exit 3 ;; esac
  done
}

# =============================================================================
# LOGGING
# =============================================================================
C_RESET=""; C_INFO=""; C_WARN=""; C_ERR=""; C_FAIL=""; C_PASS=""; C_DIM=""
setup_colors() {
  if [ -z "${NO_COLOR:-}" ] && [ -t 2 ] && [ "${TERM:-dumb}" != "dumb" ]; then
    C_RESET=$'\033[0m'; C_INFO=$'\033[36m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'
    C_FAIL=$'\033[1;31m'; C_PASS=$'\033[32m'; C_DIM=$'\033[2m'
  fi
}
_log() { # level color message
  local lvl="$1" col="$2"; shift 2
  printf '%s[%s]%s %s\n' "$col" "$lvl" "$C_RESET" "$*" >&2
  [ -n "$LOG_FILE" ] && printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$lvl" "$*" >> "$LOG_FILE" 2>/dev/null
  return 0
}
log_info()    { _log INFO "$C_INFO" "$@"; }
log_warn()    { _log WARN "$C_WARN" "$@"; }
log_error()   { _log ERROR "$C_ERR" "$@"; }
log_fail()    { _log FAIL "$C_FAIL" "$@"; }
log_pass()    { [ "$VERBOSE" = true ] && _log PASS "$C_PASS" "$@"; return 0; }
log_verbose() { [ "$VERBOSE" = true ] && _log INFO "$C_DIM" "$@"; return 0; }
log_debug()   { [ "$DEBUG" = true ] && _log DEBUG "$C_DIM" "$@"; return 0; }

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# =============================================================================
# READ-ONLY GUARD
# Every az invocation in this script goes through az() below, which calls
# az_guard. Only these are permitted:
#   az version | az account show | az account list | az cloud show
#   az rest --method get  <url>
#   az rest --method post <ARM>/providers/Microsoft.ResourceGraph/resources?...   (read-only query)
#   az rest --method post <LA>/v1/workspaces/<guid>/query                         (read-only KQL query)
# Secret-bearing endpoints (listKeys, SAS, connection strings, ...) are blocked
# for every method.
# =============================================================================
az_guard() {
  local sub="${1:-}" op="${2:-}" method="get" url="" prev="" a lurl
  case "$sub" in
    version) return 0 ;;
    account) [ "$op" = "show" ] || [ "$op" = "list" ]; return $? ;;
    cloud)   [ "$op" = "show" ]; return $? ;;
    rest) ;;
    *) return 1 ;;
  esac
  for a in "$@"; do
    case "$prev" in --method|-m) method="$a" ;; --url|--uri|-u) url="$a" ;; esac
    prev="$a"
  done
  method="$(lower "$method")"; lurl="$(lower "$url")"
  [ -n "$lurl" ] || return 1
  local secret_re='(listkeys|listconnectionstrings|regeneratekey|listaccountsas|listservicesas|listcredential|publishingcredentials|/secrets([/?]|$)|getsecret|listsecrets|/sharedkeys|generatesas|listsastoken|/keys([/?]|$))'
  if [[ "$lurl" =~ $secret_re ]]; then return 1; fi
  case "$method" in
    get) return 0 ;;
    post)
      case "$lurl" in
        "$ARM_LC/providers/microsoft.resourcegraph/resources?"*) return 0 ;;
      esac
      local la_lc; la_lc="$(lower "$LA_QUERY_ENDPOINT")"
      local la_re="^${la_lc//./\\.}/v1/workspaces/[0-9a-f-]+/query\$"
      if [[ "$lurl" =~ $la_re ]]; then return 0; fi
      return 1 ;;
    *) return 1 ;;
  esac
}

az() {
  if ! az_guard "$@"; then
    printf 'READ_ONLY_GUARD: blocked non-read-only az invocation (az %s %s)\n' "${1:-}" "${2:-}" >&2
    return $RC_BLOCKED
  fi
  if [ -n "$TIMEOUT_BIN" ]; then
    "$TIMEOUT_BIN" "$AZ_TIMEOUT_SECONDS" "$AZ_BIN" "$@"
  else
    "$AZ_BIN" "$@"
  fi
}

# =============================================================================
# ERROR CLASSIFICATION / RETRY
# =============================================================================
classify_az_error() { # <stderr file> -> prints class
  local f="$1"
  if [ ! -s "$f" ]; then echo UNKNOWN; return; fi
  if grep -q 'READ_ONLY_GUARD' "$f"; then echo BLOCKED; return; fi
  if grep -Eiq '(Too Many Requests|TooManyRequests|RequestThrottled|throttl|Internal Server Error|InternalServerError|Bad Gateway|BadGateway|Service Unavailable|ServiceUnavailable|Gateway Time-?out|GatewayTimeout|ServerTimeout|OperationTimedOut|timed out|Connection reset|ConnectionResetError|Connection aborted|RemoteDisconnected|Temporary failure|Max retries exceeded|SSLError|IncompleteRead|ChunkedEncodingError|NameResolutionError|HTTPSConnectionPool|RetryableError)' "$f"; then echo TRANSIENT; return; fi
  if grep -Eiq '(InvalidAuthenticationTokenTenant|AuthorizationFailed|LinkedAuthorizationFailed|Forbidden|InsufficientAccountPermissions|Authorization_RequestDenied|InsufficientAccessError|does not have authorization|does not have permission|AccessDenied|Authentication_RequestFromNonPremiumTenant|PermissionDenied)' "$f"; then echo FORBIDDEN; return; fi
  if grep -Eiq "(Please run 'az login'|az login|AADSTS[0-9]+|refresh token|InvalidAuthenticationToken|ExpiredAuthenticationToken|No subscription found|interaction_required)" "$f"; then echo AUTH; return; fi
  if grep -Eiq '(ResourceTypeNotSupported|not support(ed)? diagnostic|does not support diagnostic|DiagnosticSettingsNotSupported|FeatureNotSupported|OperationNotSupported|is not supported for|SkuNotSupported|NotSupported)' "$f"; then echo UNSUPPORTED; return; fi
  if grep -Eiq '(InvalidApiVersionParameter|NoRegisteredProviderFound|InvalidResourceType|api-version .* (is )?(invalid|not supported)|UnsupportedApiVersion|MissingApiVersionParameter)' "$f"; then echo APIVERSION; return; fi
  if grep -Eiq '(ResourceNotFound|NotFound|Not Found|ResourceGroupNotFound|SubscriptionNotFound|ParentResourceNotFound|Request_ResourceNotFound|ManagementPolicyNotFound|ContainerNotFound|WorkspaceNotFound|does not exist|could not be found)' "$f"; then echo NOTFOUND; return; fi
  if grep -Eiq '(Bad Request|BadRequest|InvalidRequest|InvalidParameter|SemanticError|BadArgument)' "$f"; then echo BADREQUEST; return; fi
  echo UNKNOWN
}

rc_of_class() {
  case "$1" in
    FORBIDDEN) echo $RC_FORBIDDEN ;; NOTFOUND) echo $RC_NOTFOUND ;; UNSUPPORTED) echo $RC_UNSUPPORTED ;;
    APIVERSION) echo $RC_APIVERSION ;; BADREQUEST) echo $RC_BADREQUEST ;; AUTH) echo $RC_AUTH ;;
    BLOCKED) echo $RC_BLOCKED ;; *) echo $RC_ERROR ;;
  esac
}
rc_name() {
  case "$1" in
    0) echo OK ;; 3) echo FORBIDDEN ;; 4) echo NOTFOUND ;; 5) echo UNSUPPORTED ;; 6) echo APIVERSION ;;
    7) echo BADREQUEST ;; 8) echo AUTH ;; 97) echo BLOCKED ;; *) echo ERROR ;;
  esac
}
# Maps an API return code to the compliance status used when evidence is missing.
rc_status() {
  case "$1" in
    3|8) echo NOT_VERIFIABLE ;; 5) echo NOT_APPLICABLE ;; 4) echo NOT_VERIFIABLE ;; *) echo ERROR ;;
  esac
}

# Single-line, redacted error message for a failed request.
err_msg() { # <out file>
  local f="$1.err"
  [ -s "$f" ] || { echo "no error output"; return; }
  tr '\n\r\t' '   ' < "$f" | sed -E \
      -e 's/^ *ERROR: *//' \
      -e 's/([Ss]ig|SharedAccessSignature|AccountKey|SharedAccessKey|[Pp]assword|[Tt]oken)=[^&" ;]*/\1=***REDACTED***/g' \
      -e 's/Bearer [A-Za-z0-9._-]+/Bearer ***REDACTED***/g' \
      -e 's/  +/ /g' | cut -c1-600
}

# Generic retry helper: retry <max> <cmd...> ; retries on any non-zero exit.
retry() {
  local max="$1"; shift
  local n=0 delay="$RETRY_BASE_DELAY" rc
  while :; do
    "$@"; rc=$?
    [ $rc -eq 0 ] && return 0
    n=$((n + 1))
    [ $n -gt "$max" ] && return $rc
    sleep "$delay"; delay=$((delay * 2))
  done
}

# az_call <method> <url> <out_file> [extra az rest args...]
# Executes one az rest request with retry/backoff on transient errors.
# Output JSON (validated) goes to <out_file>, error text to <out_file>.err.
az_call() {
  local method="$1" url="$2" out="$3"; shift 3
  local attempt=0 delay="$RETRY_BASE_DELAY" rc cls jitter
  while :; do
    attempt=$((attempt + 1))
    log_debug "az rest $method $url (attempt $attempt)"
    az rest --method "$method" --url "$url" --only-show-errors --output json "$@" >"$out" 2>"$out.err"
    rc=$?
    if [ $rc -eq 0 ]; then
      [ -s "$out" ] || echo 'null' > "$out"
      if jq empty "$out" >/dev/null 2>&1; then
        rm -f "$out.err"; return $RC_OK
      fi
      echo "Malformed JSON response" > "$out.err"; cls=TRANSIENT
    elif [ $rc -eq $RC_BLOCKED ]; then
      cls=BLOCKED
    elif [ $rc -eq 124 ]; then
      echo "Request timed out after ${AZ_TIMEOUT_SECONDS}s" >> "$out.err"; cls=TRANSIENT
    else
      cls="$(classify_az_error "$out.err")"
    fi
    if [ "$cls" = TRANSIENT ] && [ $attempt -le "$MAX_RETRIES" ]; then
      jitter=$((RANDOM % 3))
      log_debug "transient error ($(err_msg "$out" | cut -c1-120)); retry in $((delay + jitter))s"
      sleep $((delay + jitter)); delay=$((delay * 2))
      continue
    fi
    return "$(rc_of_class "$cls")"
  done
}

arm_url() { # <path-or-url> <api-version>
  local p="$1" v="$2" base
  case "$p" in https://*) base="$p" ;; *) base="$ARM$p" ;; esac
  case "$base" in *\?*) printf '%s&api-version=%s' "$base" "$v" ;; *) printf '%s?api-version=%s' "$base" "$v" ;; esac
}

# arm_get <path> <out> <api-versions...> : single object GET with API-version fallback.
arm_get() {
  local path="$1" out="$2"; shift 2
  local v rc=$RC_ERROR
  # shellcheck disable=SC2048,SC2086  # version lists are intentionally word-split
  for v in $*; do
    az_call get "$(arm_url "$path" "$v")" "$out"; rc=$?
    [ $rc -eq $RC_APIVERSION ] || { echo "$v" > "$out.apiversion"; return $rc; }
    log_debug "API version $v rejected for $path; trying fallback"
  done
  return $rc
}

# get_all_pages <first-url> <out> : follows nextLink / @odata.nextLink and
# writes a JSON array of all items. Incomplete pagination is an error (never
# silently truncated).
get_all_pages() {
  local url="$1" out="$2" page=0 rc next prev_urls=" "
  echo '[]' > "$out.acc"
  while [ -n "$url" ]; do
    page=$((page + 1))
    if [ $page -gt "$MAX_PAGES" ]; then
      echo "INCOMPLETE_PAGINATION: page limit MAX_PAGES=$MAX_PAGES exceeded" > "$out.err"
      rm -f "$out.acc" "$out.pg"; return $RC_ERROR
    fi
    az_call get "$url" "$out.pg"; rc=$?
    if [ $rc -ne 0 ]; then
      if [ $page -gt 1 ]; then
        printf 'INCOMPLETE_PAGINATION after page %s: %s\n' "$((page - 1))" "$(err_msg "$out.pg")" > "$out.err"
        rc=$RC_ERROR
      else
        mv -f "$out.pg.err" "$out.err" 2>/dev/null
      fi
      rm -f "$out.acc" "$out.pg" "$out.pg.err"; return $rc
    fi
    if ! jq -s '.[0] + ((.[1]) as $p | if ($p|type) == "object" then ($p.value // []) elif ($p|type) == "array" then $p else [] end)' \
         "$out.acc" "$out.pg" > "$out.acc2" 2>/dev/null; then
      echo "Malformed page $page" > "$out.err"; rm -f "$out.acc" "$out.acc2" "$out.pg"; return $RC_ERROR
    fi
    mv -f "$out.acc2" "$out.acc"
    next="$(jq -r 'if type == "object" then (.nextLink // .["@odata.nextLink"] // "") else "" end' "$out.pg" 2>/dev/null)"
    if [ -n "$next" ]; then
      case "$prev_urls" in *" $next "*)
        echo "INCOMPLETE_PAGINATION: nextLink loop detected" > "$out.err"; rm -f "$out.acc" "$out.pg"; return $RC_ERROR ;;
      esac
      prev_urls="$prev_urls$url "
    fi
    url="$next"
  done
  mv -f "$out.acc" "$out"; rm -f "$out.pg"
  return $RC_OK
}

# arm_list <path> <out> <api-versions...> : paged list with API-version fallback.
arm_list() {
  local path="$1" out="$2"; shift 2
  local v rc=$RC_ERROR
  # shellcheck disable=SC2048,SC2086  # version lists are intentionally word-split
  for v in $*; do
    get_all_pages "$(arm_url "$path" "$v")" "$out"; rc=$?
    [ $rc -eq $RC_APIVERSION ] || { echo "$v" > "$out.apiversion"; return $rc; }
  done
  return $rc
}

# az_json <out> <az args...> : run an allowed az command returning JSON (with retry).
az_json() {
  local out="$1"; shift
  local attempt=0 delay="$RETRY_BASE_DELAY" rc cls
  while :; do
    attempt=$((attempt + 1))
    az "$@" --only-show-errors --output json >"$out" 2>"$out.err"; rc=$?
    if [ $rc -eq 0 ] && jq empty "$out" >/dev/null 2>&1; then rm -f "$out.err"; return 0; fi
    [ $rc -eq 0 ] && echo "Malformed JSON" > "$out.err"
    cls="$(classify_az_error "$out.err")"
    if [ "$cls" = TRANSIENT ] && [ $attempt -le "$MAX_RETRIES" ]; then sleep "$delay"; delay=$((delay * 2)); continue; fi
    return "$(rc_of_class "$cls")"
  done
}

# az_safe <az args...> : run an allowed az command, discard output, return rc.
az_safe() {
  local t; t="$(tmpf)"
  az_json "$t" "$@"; local rc=$?
  rm -f "$t" "$t.err"; return $rc
}

# arg_query <subscription-id> <kql> <out> : Azure Resource Graph query with
# $skipToken paging. (POST is required by the ARG API; the query is read-only.)
arg_query() {
  local sub="$1" kql="$2" out="$3" token="" page=0 rc body
  echo '[]' > "$out.acc"
  while :; do
    page=$((page + 1))
    [ $page -gt "$MAX_PAGES" ] && { echo "INCOMPLETE_PAGINATION: ARG page limit" > "$out.err"; return $RC_ERROR; }
    body="$out.body"
    jq -n --arg s "$sub" --arg q "$kql" --arg t "$token" \
      '{subscriptions: [$s], query: $q, options: ({resultFormat: "objectArray", "$top": 1000} + (if $t != "" then {"$skipToken": $t} else {} end))}' > "$body"
    az_call post "$(arm_url "/providers/Microsoft.ResourceGraph/resources" "$API_ARG")" "$out.pg" \
      --body "@$body" --headers "Content-Type=application/json"; rc=$?
    if [ $rc -ne 0 ]; then
      mv -f "$out.pg.err" "$out.err" 2>/dev/null
      [ $page -gt 1 ] && { printf 'INCOMPLETE_PAGINATION (ARG) after page %s: %s\n' "$((page-1))" "$(cat "$out.err" 2>/dev/null)" > "$out.err.tmp"; mv -f "$out.err.tmp" "$out.err"; rc=$RC_ERROR; }
      rm -f "$out.acc" "$out.pg" "$body"; return $rc
    fi
    jq -s '.[0] + (.[1].data // [])' "$out.acc" "$out.pg" > "$out.acc2" && mv -f "$out.acc2" "$out.acc"
    if [ "$(jq -r '(.resultTruncated // "false") | tostring' "$out.pg")" = "true" ] && [ -z "$(jq -r '.["$skipToken"] // ""' "$out.pg")" ]; then
      echo "INCOMPLETE_PAGINATION: ARG result truncated without skipToken" > "$out.err"; rm -f "$out.acc" "$out.pg" "$body"; return $RC_ERROR
    fi
    token="$(jq -r '.["$skipToken"] // ""' "$out.pg")"
    [ -n "$token" ] || break
  done
  mv -f "$out.acc" "$out"; rm -f "$out.pg" "$body"
  return $RC_OK
}

# la_query <workspace customerId> <kql> <timespan ISO8601> <out> : Log Analytics
# query API (POST /v1/workspaces/{id}/query). Result converted to array of objects.
la_query() {
  local wsid="$1" kql="$2" span="$3" out="$4" rc
  jq -n --arg q "$kql" --arg t "$span" '{query: $q, timespan: $t}' > "$out.body"
  az_call post "${LA_QUERY_ENDPOINT%/}/v1/workspaces/$wsid/query" "$out.raw" \
    --resource "$LA_QUERY_ENDPOINT" --body "@$out.body" --headers "Content-Type=application/json"; rc=$?
  rm -f "$out.body"
  if [ $rc -ne 0 ]; then mv -f "$out.raw.err" "$out.err" 2>/dev/null; rm -f "$out.raw"; return $rc; fi
  jq '(.tables[0] // {columns: [], rows: []}) as $t
      | [ $t.rows[] as $r | [$t.columns, $r] | transpose | map({key: .[0].name, value: .[1]}) | from_entries ]' \
     "$out.raw" > "$out" 2>/dev/null || { echo "Malformed query result" > "$out.err"; rm -f "$out.raw"; return $RC_ERROR; }
  rm -f "$out.raw"
  return $RC_OK
}

# =============================================================================
# FILES / RECORDS / FINDINGS
# =============================================================================
tmpf() { mktemp "$WORK/tmp/t.XXXXXXXX"; }

safe_name() { # resource id -> safe file name
  local s ck
  s="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -e 's#^/subscriptions/##' -e 's#[^a-z0-9._-]#_#g')"
  if [ ${#s} -gt 150 ]; then ck="$(printf '%s' "$1" | cksum | cut -d' ' -f1)"; s="${s:0:130}_$ck"; fi
  printf '%s' "$s"
}

# save_raw <category> <id> <json file> : stores redacted evidence, prints relative path.
save_raw() {
  local cat="$1" id="$2" f="$3" rel
  [ "$SAVE_RAW" = true ] || { printf ''; return 0; }
  [ -s "$f" ] || { printf ''; return 0; }
  mkdir -p "$RAW_DIR/$cat"
  rel="raw/$cat/$(safe_name "$id").json"
  if ! jqlib 'redact' "$f" > "$RUN_DIR/$rel" 2>/dev/null; then rm -f "$RUN_DIR/$rel"; printf ''; return 0; fi
  printf '%s' "$rel"
}

jqlib() { # <program> [jq args...]
  local prog="$1"; shift
  jq -L "$JQLIB_DIR" "include \"lib\"; $prog" "$@"
}

emit() { # <stream> <json-line>
  printf '%s\n' "$2" >> "$SHARD_DIR/$1.jsonl"
}
emit_file() { # <stream> <jsonl file>
  [ -s "$2" ] && cat "$2" >> "$SHARD_DIR/$1.jsonl"
  return 0
}

record_error() { # <area> <operation> <resourceId> <code> <message> [subscriptionId]
  jq -nc --arg area "$1" --arg operation "$2" --arg resourceId "$3" --arg code "$4" \
         --arg message "$5" --arg subscriptionId "${6:-}" --arg ts "$(now_iso)" \
     '{timestamp: $ts, area: $area, operation: $operation,
       subscriptionId: (if $subscriptionId != "" then $subscriptionId else ((($resourceId | capture("^/subscriptions/(?<s>[^/]+)"; "i").s) // "") | ascii_downcase) end),
       resourceId: $resourceId, code: $code, message: $message}' >> "$SHARD_DIR/errors.jsonl"
  log_debug "error [$4] $1/$2 $3: $5"
}
add_error() { record_error "$@"; }

# add_finding key=value ... (keys: control status severity subscriptionId resourceId
# resourceType resourceName resourceGroup evidence expected actual reason recommendation evidenceFile title)
add_finding() {
  local args=() kv k v t
  for kv in "$@"; do k="${kv%%=*}"; v="${kv#*=}"; args+=(--arg "$k" "$v"); done
  t="$(tmpf)"
  jq -nc -L "$JQLIB_DIR" "${args[@]}" --arg __ts "$(now_iso)" --slurpfile __subs "$WORK/subnames.json" \
     'include "lib"; $ARGS.named | del(.__ts) | mkfinding($__ts; $__subs[0])' > "$t" 2>/dev/null
  if [ -s "$t" ]; then
    cat "$t" >> "$SHARD_DIR/findings.jsonl"
    print_findings "$t"
  else
    log_error "internal: could not serialize finding ($*)"
  fi
  rm -f "$t"
}

# ingest_findings <jsonl of raw finding objects> : normalizes, stores, prints.
ingest_findings() {
  local f="$1" t
  [ -s "$f" ] || return 0
  t="$(tmpf)"
  jqlib 'mkfinding($ts; $subs[0])' -c --arg ts "$(now_iso)" --slurpfile subs "$WORK/subnames.json" "$f" > "$t" 2>"$t.err"
  if [ -s "$t.err" ]; then log_error "internal: finding normalization failed: $(head -c 300 "$t.err")"; fi
  cat "$t" >> "$SHARD_DIR/findings.jsonl"
  print_findings "$t"
  rm -f "$t" "$t.err"
}

# Console output: FAIL/ERROR/WARNING(>=MEDIUM) always; everything with --verbose.
print_findings() {
  local line
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      FAIL*)           log_fail "${line#FAIL|}" ;;
      ERROR*)          log_error "${line#ERROR|}" ;;
      WARNING*)        log_warn "${line#WARNING|}" ;;
      PASS*)           log_pass "${line#PASS|}" ;;
      *)               log_verbose "${line#*|}" ;;
    esac
  done < <(jq -r --arg v "$VERBOSE" '
      select($v == "true" or .status == "FAIL" or .status == "ERROR"
             or (.status == "WARNING" and (.severity == "CRITICAL" or .severity == "HIGH" or .severity == "MEDIUM")))
      | "\(.status)|\(.control) [\(.severity)] \(.resourceName // "")\(if (.actual // "") != "" then ": " + (.actual | .[0:180]) else "" end)"' "$1" 2>/dev/null)
}

# =============================================================================
# PARALLEL JOB POOL (bash 3.2 compatible; each job writes to its own shard)
# =============================================================================
pool_run() { # <function> [args...]
  if [ "$PARALLEL" != true ]; then "$@"; return $?; fi
  while [ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$MAX_PARALLEL" ]; do sleep 0.2; done
  JOB_SEQ=$((JOB_SEQ + 1))
  local shard="$WORK/shards/j$$-$JOB_SEQ-$RANDOM"
  ( SHARD_DIR="$shard"; mkdir -p "$SHARD_DIR"; "$@" ) &
}
pool_wait() { [ "$PARALLEL" = true ] && wait; return 0; }

# Merge all shards of one stream into a single JSONL file.
merged() { # <stream> -> prints path of merged file
  local s="$1" f="$WORK/merged/$1.jsonl"
  mkdir -p "$WORK/merged"
  : > "$f"
  find "$WORK/shards" -type f -name "$s.jsonl" -print 2>/dev/null | LC_ALL=C sort | while IFS= read -r x; do
    jq -cR 'fromjson? // empty' "$x" >> "$f" 2>/dev/null
  done
  printf '%s' "$f"
}

# =============================================================================
# JQ LIBRARY (evaluation logic lives here so that bulk evaluation is done in a
# single jq process per object instead of thousands of shell round trips)
# =============================================================================
write_jq_lib() {
  cat > "$JQLIB_DIR/lib.jq" <<'JQEOF'
def lc: if . == null then "" else tostring | ascii_downcase end;
def s: if . == null then "" elif type == "string" then . elif type == "array" then (map(if type == "string" then . else tojson end) | join("; ")) else tojson end;
def rx($re): if ($re // "") == "" then false else (tostring | test($re; "i")) end;
def rwalk(f): def w: if type == "object" then map_values(w) | f elif type == "array" then map(w) | f else f end; w;
def rg_of: ((tostring | capture("/resourcegroups/(?<rg>[^/]+)"; "i").rg) // "");
def name_of: ((tostring | split("/") | map(select(. != "")) | last) // "");
def sub_of: ((tostring | capture("^/subscriptions/(?<s>[^/]+)"; "i").s | ascii_downcase) // "");
def inter($a; $b): ($a | map(lc)) as $bl | [$b[] | select(. as $x | $bl | index($x | lc))] | unique;

# ---- secret redaction ----------------------------------------------------------
def secret_key_re: "^(primarykey|secondarykey|primaryconnectionstring|secondaryconnectionstring|connectionstring|.*password.*|.*secret.*|accesskey|storageaccountaccesskey|sastoken|sasuri|saskey|sharedaccesskey|accountkey|instrumentationkey|.*token|credential|credentials|privatekey|key1|key2|aliasprimaryconnectionstring|aliassecondaryconnectionstring)$";
def redact:
  rwalk(if type == "object" then
          with_entries(
            if (.value | type) == "string" and ((.key | lc | test(secret_key_re))
                 or (.value | test("(SharedAccessKey=|AccountKey=|[?&]sig=|SharedAccessSignature |Password=|InstrumentationKey=)"; "i")))
            then .value = "***REDACTED***" else . end)
        else . end);

# ---- CSV --------------------------------------------------------------------------
def csvcell: s | if test("^[=+@\t\r]") or test("^-[^0-9]") then "'" + . else . end;
def csvrow: map(csvcell) | @csv;

# ---- findings ----------------------------------------------------------------------
def control_titles: {
  "SUB-001": "Subscription audited",
  "LOG-001": "Diagnostic Settings present (log categories enabled)",
  "LOG-002": "Required logging categories enabled",
  "LOG-003": "Central LAW destination present",
  "LOG-004": "Archive (Storage) destination present",
  "LOG-005": "Archive destination is locked WORM storage",
  "LOG-006": "All available log categories enabled",
  "LOG-007": "Direct Event Hub streaming (policy)",
  "LOGCAT-001": "Resource uses legacy AzureDiagnostics mode",
  "LOGCAT-002": "AzureDiagnostics table usage in workspace",
  "LOGCAT-003": "Workspace table strategy (App* / CustomLogs)",
  "LAW-001": "LAW default retention >= required threshold",
  "LAW-002": "Table retention compliant",
  "LAW-003": "LAW Data Export to Event Hub configured",
  "LAW-004": "Exportable LAW tables exported",
  "LAW-005": "Active tables that cannot be exported",
  "LAW-006": "LAW daily ingestion cap",
  "LAW-007": "LAW network access / local authentication",
  "LAW-008": "LAW pricing tier",
  "EH-001": "Security Event Hub exists",
  "EH-002": "LAW -> Event Hub path configured",
  "EH-003": "Event Hub network configuration reviewed",
  "EH-004": "Downstream Cribl connectivity",
  "EH-005": "Azure-side Event Hub delivery evidence",
  "EH-006": "Event Hub security hardening (TLS / local auth)",
  "EH-007": "Security Event Hub retention / capacity",
  "ARC-001": "Archive storage configured",
  "ARC-002": "Blob versioning enabled",
  "ARC-003": "Soft delete enabled",
  "ARC-004": "Immutability enabled",
  "ARC-005": "Immutability LOCKED",
  "ARC-006": "Immutable retention >= minimum",
  "ARC-007": "Immutable retention >= preferred target",
  "ARC-008": "Lifecycle policy does not delete before retention",
  "ARC-009": "Archive transport / network security",
  "ARC-010": "Change feed enabled",
  "ARC-011": "Protected append writes for diagnostic log containers",
  "ARC-012": "Shared key / anonymous blob access",
  "ACT-001": "Subscription Activity Logs exported to LAW",
  "ACT-002": "Subscription Activity Logs archived to immutable storage",
  "ACT-003": "Subscription Activity Logs reach Event Hub",
  "ACT-004": "All expected Activity Log categories exported",
  "DB-001": "Database auditing enabled",
  "DB-002": "Database audit logs centrally collected",
  "DB-003": "Database audit retention / archive",
  "DB-004": "Database audit configuration quality",
  "DB-005": "Microsoft support operations auditing",
  "ENTRA-001": "Entra AuditLogs collected",
  "ENTRA-002": "Entra SignInLogs collected",
  "ENTRA-003": "Entra NonInteractiveUserSignInLogs collected",
  "ENTRA-004": "Entra ServicePrincipalSignInLogs collected",
  "ENTRA-005": "Entra ManagedIdentitySignInLogs collected",
  "ENTRA-006": "Entra ProvisioningLogs collected",
  "ENTRA-007": "Entra risk logs collected",
  "ENTRA-008": "Entra logs archive / streaming path",
  "DBX-001": "Databricks tier supports diagnostic logs",
  "DBX-002": "Databricks Unity Catalog audit category enabled",
  "DBX-003": "Databricks access / account audit categories enabled",
  "DBX-004": "Databricks verbose audit / data-plane audit settings",
  "DBX-005": "Databricks system tables / lineage",
  "APP-001": "Application Insights workspace based",
  "APP-002": "Application telemetry reaches Event Hub pipeline",
  "APP-003": "Application Insights local authentication",
  "UWWB-001": "Application CRUD audit logging evidence",
  "UWWB-002": "Application audit schema avoids payload fields",
  "RBAC-001": "Logging access follows read-only model",
  "RBAC-002": "Expected reader groups hold read-only roles",
  "RBAC-003": "Expected reader groups discoverable on LAW"
};
def regulatory($c):
  if ($c | startswith("RBAC")) then
    "Technical control evidence supporting: ISO/IEC 27001:2022 A.5.15, A.8.2, A.8.15; DORA Art. 12 (logging, see RTS (EU) 2024/1774 Art. 12)"
  elif ($c | startswith("SUB")) then "Audit coverage"
  else
    "Technical control evidence supporting: ISO/IEC 27001:2022 A.5.28, A.8.15; DORA Art. 12 (logging, see RTS (EU) 2024/1774 Art. 12)"
  end;
def valid_status: if IN("PASS", "FAIL", "WARNING", "NOT_APPLICABLE", "NOT_VERIFIABLE", "ERROR") then . else "ERROR" end;
def valid_sev: if IN("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") then . else "MEDIUM" end;
def mkfinding($ts; $subs):
  . as $f
  | (($f.status // "NOT_VERIFIABLE") | valid_status) as $st
  | ($f.resourceId // "") as $rid
  | {
      control: ($f.control // "UNKNOWN"),
      title: ($f.title // control_titles[$f.control // ""] // ""),
      status: $st,
      severity: (if $st == "PASS" or $st == "NOT_APPLICABLE" then "INFO" else (($f.severity // "MEDIUM") | valid_sev) end),
      subscriptionId: (($f.subscriptionId // ($rid | sub_of)) | lc),
      subscriptionName: ($f.subscriptionName // $subs[(($f.subscriptionId // ($rid | sub_of)) | lc)] // ""),
      resourceGroup: ($f.resourceGroup // ($rid | rg_of)),
      resourceId: $rid,
      resourceType: ($f.resourceType // ""),
      resourceName: ($f.resourceName // ($rid | name_of)),
      evidence: ($f.evidence // "" | s),
      expected: ($f.expected // "" | s),
      actual: ($f.actual // "" | s),
      reason: ($f.reason // "" | s),
      recommendation: ($f.recommendation // "" | s),
      regulatory: regulatory($f.control // ""),
      evidenceFile: ($f.evidenceFile // ""),
      timestamp: $ts
    };

# ---- Diagnostic settings evaluation ----------------------------------------------------
def expand_entry($logNames; $groupsOf):
  if ((.category // "") | tostring) != "" then [ .category ]
  elif ((.categoryGroup // "") | tostring) != "" then
    (.categoryGroup | lc) as $g
    | if $g == "alllogs" then $logNames
      else [ $logNames[] | select((($groupsOf[lc]) // []) | index($g)) ] end
  else [] end;
def canon($logNames): . as $n | (([$logNames[] | select(lc == ($n | lc))] | first) // $n);
def eh_ns_of_rule: if (. // "") == "" then null else sub("/authorizationrules/[^/]+$"; ""; "i") end;

# Summarize a list of diagnostic settings, expanding category groups.
def settings_eval($logNames; $groupsOf):
  map((.properties // {}) as $p
      | ([($p.logs // [])[] | select(.enabled == true) | expand_entry($logNames; $groupsOf)[] | canon($logNames)] | unique) as $en
      | { name: (.name // ""),
          workspaceId: ($p.workspaceId // null),
          storageAccountId: ($p.storageAccountId // null),
          eventHubAuthorizationRuleId: ($p.eventHubAuthorizationRuleId // null),
          eventHubNamespaceId: ($p.eventHubAuthorizationRuleId | eh_ns_of_rule),
          eventHubName: ($p.eventHubName // null),
          marketplacePartnerId: ($p.marketplacePartnerId // null),
          serviceBusRuleId: ($p.serviceBusRuleId // null),
          logAnalyticsDestinationType: ($p.logAnalyticsDestinationType // null),
          enabledCategories: $en,
          enabledGroups: [($p.logs // [])[] | select(.enabled == true and ((.categoryGroup // "") != "")) | .categoryGroup],
          metricsEnabled: ([($p.metrics // [])[] | select(.enabled == true)] | length > 0),
          legacyRetentionDays: ([($p.logs // [])[] | select(.enabled == true and (.retentionPolicy.enabled // false) and ((.retentionPolicy.days // 0) > 0)) | .retentionPolicy.days] | min)
        });

def settings_summary:
  map(.name + " [" + ([ (if .workspaceId then "LAW:" + (.workspaceId | name_of) + (if ((.logAnalyticsDestinationType // "") | lc) == "dedicated" then "(resource-specific)" else "(AzureDiagnostics)" end) else empty end),
                        (if .storageAccountId then "Storage:" + (.storageAccountId | name_of) else empty end),
                        (if .eventHubNamespaceId then "EventHub:" + (.eventHubNamespaceId | name_of) + "/" + (.eventHubName // "(per-category hubs)") else empty end),
                        (if .marketplacePartnerId then "Partner" else empty end)] | join(", "))
      + "] logs=" + (if (.enabledCategories | length) == 0 then "none" else (.enabledCategories | join("|")) end)
      + " metrics=" + (.metricsEnabled | tostring)) | join("; ");

def diag_eval($cfg):
  .resource as $res
  | (.categories // []) as $cats
  | (.settings // []) as $settings
  | [$cats[] | select(((.properties.categoryType // "") | lc) == "logs") | .name] as $logNames
  | [$cats[] | select(((.properties.categoryType // "") | lc) == "metrics") | .name] as $metricNames
  | ([$cats[] | select(((.properties.categoryType // "") | lc) == "logs") | {key: (.name | lc), value: ((.properties.categoryGroups // []) | map(lc))}] | from_entries) as $groupsOf
  | ([$cats[] | (.properties.categoryGroups // [])[] | lc] | unique) as $groupsAvail
  | ($settings | settings_eval($logNames; $groupsOf)) as $S
  | ([$S[].enabledCategories[]] | unique) as $enabled
  | ([$S[] | select(.workspaceId != null) | .enabledCategories[]] | unique) as $toLaw
  | ([$S[] | select(.storageAccountId != null) | .enabledCategories[]] | unique) as $toSto
  | ([$S[] | select(.eventHubAuthorizationRuleId != null) | .enabledCategories[]] | unique) as $toEh
  | (if $cfg.requiredMode == "all" then {basis: "ALL_LOGS_POLICY", req: $logNames}
     else ([$logNames[] | select((($groupsOf[lc]) // []) | index("audit"))]) as $aud
       | ([$logNames[] | select(rx($cfg.requiredCategoryRegex))]) as $rxm
       | if ($aud | length) > 0 then {basis: "AUDIT_CATEGORY_GROUP", req: ($aud + $rxm | unique)}
         elif ($rxm | length) > 0 then {basis: "CATEGORY_NAME_REGEX", req: ($rxm | unique)}
         else {basis: "ALL_LOGS_FALLBACK", req: $logNames} end
     end) as $R
  | $R.req as $req
  | ($res.subscriptionName // "") as $subName
  | (([$subName, ($res.resourceGroup // ""), ($res.name // "")]
      + [($res.tags // {}) | to_entries[] | select(.key | test("env|environment|stage"; "i")) | .value | tostring])
     | any(rx($cfg.prodRegex))) as $isProd
  | {
      id: $res.id, name: $res.name, type: $res.type, kind: ($res.kind // null), location: ($res.location // null),
      resourceGroup: ($res.resourceGroup // ($res.id | rg_of)), subscriptionId: ($res.subscriptionId | lc), subscriptionName: $subName,
      parentId: ($res.parentId // null),
      isProd: $isProd, isCritical: ($res.type | rx($cfg.criticalTypesRegex)),
      auditStatus: "OK", auditError: "", supported: true,
      logCategories: $logNames, metricCategories: $metricNames, categoryGroupsAvailable: $groupsAvail,
      settingsCount: ($S | length), settings: $S, settingsSummary: ($S | settings_summary),
      enabledCategories: $enabled,
      missingCategories: ($logNames - $enabled),
      requiredBasis: $R.basis, requiredCategories: $req,
      missingRequired: ($req - $enabled),
      requiredToLaw: ($req - ($req - $toLaw)),
      requiredNotToLaw: ($req - $toLaw),
      requiredNotToStorage: ($req - $toSto),
      requiredNotToEventHub: ($req - $toEh),
      categoriesToLaw: $toLaw, categoriesToStorage: $toSto, categoriesToEventHub: $toEh,
      workspaces: ([$S[].workspaceId | select(. != null) | lc] | unique),
      storageAccounts: ([$S[].storageAccountId | select(. != null) | lc] | unique),
      eventHubNamespaces: ([$S[].eventHubNamespaceId | select(. != null) | lc] | unique),
      eventHubNames: ([$S[].eventHubName | select(. != null)] | unique),
      metricsEnabled: ([$S[].metricsEnabled] | any),
      allLogsEnabled: (($logNames | length) > 0 and (($logNames - $enabled) | length) == 0),
      azureDiagnosticsMode: ([$S[] | select(.workspaceId != null and ((.logAnalyticsDestinationType // "") | lc) != "dedicated" and (.enabledCategories | length) > 0)] | length > 0),
      dedicatedMode: ([$S[] | select(.workspaceId != null and ((.logAnalyticsDestinationType // "") | lc) == "dedicated")] | length > 0),
      legacyRetentionDays: ([$S[].legacyRetentionDays | select(. != null)] | min),
      evidenceFile: ($res.evidenceFile // "")
    }
  | .coverage = (if (.logCategories | length) == 0 then "METRICS_ONLY_RESOURCE"
                 elif .settingsCount == 0 then "NONE"
                 elif (.enabledCategories | length) == 0 then "METRICS_ONLY"
                 elif (.missingRequired | length) == 0 and (.requiredNotToLaw | length) == 0 then "FULL"
                 else "PARTIAL" end);

def sev_scale: if .isProd and .isCritical then "CRITICAL" elif (.isProd or .isCritical) then "HIGH" else "MEDIUM" end;
def fbase: {subscriptionId, subscriptionName, resourceGroup, resourceId: .id, resourceType: .type, resourceName: .name, evidenceFile: (.evidenceFile // "")};

def diag_findings($cfg):
  . as $r | ($r | fbase) as $b | ($r | sev_scale) as $sev
  | ("GET " + $r.id + "/providers/Microsoft.Insights/diagnosticSettings?api-version=" + $cfg.apiDiag) as $how
  | if $r.auditStatus != "OK" then
      if $r.auditStatus == "FORBIDDEN" or $r.auditStatus == "AUTH" then
        $b + {control: "LOG-001", status: "NOT_VERIFIABLE", severity: $sev, expected: "Readable diagnostic settings",
              actual: "Diagnostic settings not readable", reason: ("HTTP 403 / permission problem (" + $r.auditStatus + "): " + $r.auditError),
              evidence: $how, recommendation: "Grant Reader (or Monitoring Reader) on this scope to the audit identity and re-run."}
      elif $r.auditStatus == "NOTFOUND" then
        $b + {control: "LOG-001", status: "NOT_VERIFIABLE", severity: "INFO", actual: "Resource not found during audit",
              reason: ("Resource was deleted or moved while the audit ran: " + $r.auditError), evidence: $how}
      elif $r.auditStatus == "SKIPPED" or $r.auditStatus == "UNSUPPORTED" then empty
      else
        $b + {control: "LOG-001", status: "ERROR", severity: "INFO", actual: "Audit request failed",
              reason: ($r.auditStatus + ": " + $r.auditError), evidence: $how}
      end
    elif ($r.logCategories | length) == 0 then empty
    elif $r.settingsCount == 0 then
      $b + {control: "LOG-001", status: "FAIL", severity: $sev,
            expected: ("Diagnostic setting enabling log categories (" + ($r.logCategories | length | tostring) + " available: " + ($r.logCategories | join(", ")) + ")"),
            actual: "No diagnostic settings configured",
            evidence: ($how + " returned 0 settings"),
            reason: "Resource emits no resource logs to any destination; only the platform Activity Log exists.",
            recommendation: "Create a diagnostic setting sending allLogs (or at least the audit category group) to the central LAW in resource-specific mode and to the immutable archive."}
    elif ($r.enabledCategories | length) == 0 then
      $b + {control: "LOG-001", status: "FAIL", severity: $sev,
            expected: "At least one diagnostic setting with enabled log categories",
            actual: ("Diagnostic settings exist but enable no log category (metrics only): " + $r.settingsSummary),
            evidence: $how, reason: "A metrics-only diagnostic setting does not provide audit/security logs.",
            recommendation: "Enable the allLogs or audit category group on the diagnostic setting."}
    else
      ($b + {control: "LOG-001", status: "PASS", actual: $r.settingsSummary, evidence: $how}),
      ( if ($r.missingRequired | length) == 0 then
          $b + {control: "LOG-002", status: "PASS", expected: ("Required categories (" + $r.requiredBasis + "): " + ($r.requiredCategories | join(", "))),
                actual: ("Enabled: " + ($r.enabledCategories | join(", "))), evidence: $how}
        else
          $b + {control: "LOG-002", status: (if $r.requiredBasis == "ALL_LOGS_FALLBACK" then "WARNING" else "FAIL" end), severity: "MEDIUM",
                expected: ("Required categories (" + $r.requiredBasis + "): " + ($r.requiredCategories | join(", "))),
                actual: ("Missing: " + ($r.missingRequired | join(", ")) + " | Enabled: " + ($r.enabledCategories | join(", "))),
                evidence: ($how + " | settings: " + $r.settingsSummary),
                reason: (if $r.requiredBasis == "ALL_LOGS_FALLBACK" then "Resource type exposes no 'audit' category group; all log categories were treated as expected, missing ones are reported as a warning." else "Security-relevant (audit group / policy regex) categories are not enabled on any diagnostic setting." end),
                recommendation: "Enable the missing categories (prefer categoryGroup 'audit' or 'allLogs')."}
        end ),
      ( if ($r.requiredNotToLaw | length) == 0 then
          ([$r.workspaces[] | name_of] ) as $wn
          | if ($cfg.centralLawRegex // "") != "" and ([$wn[] | select(rx($cfg.centralLawRegex))] | length) == 0 then
              $b + {control: "LOG-003", status: "WARNING", severity: "LOW", expected: ("Central LAW matching " + $cfg.centralLawRegex),
                    actual: ("Required categories sent to non-central LAW(s): " + ($wn | join(", "))), evidence: $how,
                    recommendation: "Route security logs to the central SOC workspace."}
            else
              $b + {control: "LOG-003", status: "PASS", actual: ("Required categories sent to LAW: " + ($wn | join(", "))), evidence: $how}
            end
        elif ($r.requiredToLaw | length) == 0 then
          $b + {control: "LOG-003", status: "FAIL", severity: $sev, expected: "Required categories delivered to a Log Analytics Workspace",
                actual: ("No required category reaches any LAW. Settings: " + $r.settingsSummary), evidence: $how,
                reason: "Security telemetry is not centrally collected for SOC monitoring.",
                recommendation: "Add the central LAW as destination of the diagnostic setting."}
        else
          $b + {control: "LOG-003", status: "WARNING", severity: "MEDIUM", expected: "All required categories delivered to LAW",
                actual: ("Not sent to LAW: " + ($r.requiredNotToLaw | join(", "))), evidence: ($how + " | " + $r.settingsSummary),
                recommendation: "Enable the missing categories on the LAW-bound diagnostic setting."}
        end ),
      ( if $cfg.archivePolicy == "off" then empty
        elif ($r.requiredNotToStorage | length) == 0 then
          $b + {control: "LOG-004", status: "PASS", actual: ("Required categories archived to: " + ($r.storageAccounts | map(name_of) | join(", "))), evidence: $how}
        else
          $b + {control: "LOG-004", status: (if $cfg.archivePolicy == "require" then "FAIL" else "WARNING" end),
                severity: (if $cfg.archivePolicy == "require" then "HIGH" else "MEDIUM" end),
                expected: "Required categories also delivered to immutable Storage archive",
                actual: (if ($r.storageAccounts | length) == 0 then "No Storage destination" else ("Not archived: " + ($r.requiredNotToStorage | join(", "))) end),
                evidence: ($how + " | " + $r.settingsSummary),
                reason: "No direct archive copy from the diagnostic setting (an archive may still exist via LAW Data Export to Storage).",
                recommendation: "Add the immutable archive Storage account as diagnostic destination, or document the LAW-export-based archive path."}
        end ),
      ( if ($r.missingCategories | length) > 0 and ($r.missingRequired | length) == 0 then
          $b + {control: "LOG-006", status: "WARNING", severity: "LOW", expected: "allLogs enabled",
                actual: ("Non-required categories not enabled: " + ($r.missingCategories | join(", "))), evidence: $how,
                recommendation: "Consider enabling categoryGroup allLogs."}
        elif ($r.missingCategories | length) == 0 then
          $b + {control: "LOG-006", status: "PASS", actual: "All available log categories enabled", evidence: $how}
        else empty end ),
      ( if $cfg.ehPolicy == "warn" and ($r.requiredNotToEventHub | length) > 0 then
          $b + {control: "LOG-007", status: "WARNING", severity: "LOW", expected: "Required categories streamed directly to Event Hub",
                actual: ("Not streamed: " + ($r.requiredNotToEventHub | join(", "))), evidence: $how,
                reason: "Policy RESOURCE_EVENTHUB_POLICY=warn. The primary architecture path is LAW Data Export (see LAW-003/EH-002)."}
        else empty end ),
      ( if $r.azureDiagnosticsMode and ($r.type | rx($cfg.dedicatedRegex)) then
          $b + {control: "LOGCAT-001", status: "WARNING", severity: "LOW", expected: "Resource-specific (Dedicated) LAW tables",
                actual: "Diagnostic setting writes to legacy AzureDiagnostics table", evidence: ($how + " | logAnalyticsDestinationType is not 'Dedicated'"),
                reason: "Governance/modernization finding: resource type supports resource-specific tables.",
                recommendation: "Set logAnalyticsDestinationType=Dedicated (export-to-resource-specific)."}
        else empty end )
    end;

# ---- WORM evaluation -----------------------------------------------------------------------
def worm_rank: {"NO_IMMUTABILITY": 0, "UNLOCKED_IMMUTABILITY": 1, "BLOB_LEVEL_UNVERIFIED": 2, "LOCKED_IMMUTABILITY": 3, "LEGAL_HOLD": 4, "LOCKED_AND_RETENTION_SUFFICIENT": 5}[.] // 0;

def container_worm($acct; $cfg):
  (.properties // {}) as $p
  | ($acct.properties.immutableStorageWithVersioning // {}) as $accVl
  | ($p.immutabilityPolicy.properties // $p.immutabilityPolicy // null) as $cp
  | (if $cp != null and (($cp.state // "") != "") and (($cp.state | lc) != "deleted") then
       {scope: "CONTAINER", state: $cp.state, days: ($cp.immutabilityPeriodSinceCreationInDays // 0),
        allowProtectedAppendWrites: ($cp.allowProtectedAppendWrites // false), allowProtectedAppendWritesAll: ($cp.allowProtectedAppendWritesAll // false)}
     elif (($p.immutableStorageWithVersioning.enabled // false) or ($accVl.enabled // false))
          and (($accVl.immutabilityPolicy.state // "") != "") and (($accVl.immutabilityPolicy.state | lc) != "disabled") then
       {scope: "ACCOUNT_DEFAULT", state: $accVl.immutabilityPolicy.state, days: ($accVl.immutabilityPolicy.immutabilityPeriodSinceCreationInDays // 0),
        allowProtectedAppendWrites: ($accVl.immutabilityPolicy.allowProtectedAppendWrites // false), allowProtectedAppendWritesAll: false}
     else null end) as $eff
  | (($p.legalHold.hasLegalHold // $p.hasLegalHold) // false) as $lh
  | (($p.immutableStorageWithVersioning.enabled // false) or ($accVl.enabled // false)) as $vl
  | (if $eff != null and (($eff.state | lc) == "locked") then
       (if ($eff.days >= $cfg.archiveMin) then "LOCKED_AND_RETENTION_SUFFICIENT" else "LOCKED_IMMUTABILITY" end)
     elif $eff != null and (($eff.state | lc) == "unlocked") then "UNLOCKED_IMMUTABILITY"
     elif $lh then "LEGAL_HOLD"
     elif $vl then "BLOB_LEVEL_UNVERIFIED"
     else "NO_IMMUTABILITY" end) as $ws
  | {
      storageAccountId: ($acct.id | lc), storageAccountName: $acct.name, subscriptionId: ($acct.id | sub_of),
      container: .name, isLogContainer: (.name | rx($cfg.logContainerRegex)),
      hasImmutabilityPolicy: ($p.hasImmutabilityPolicy // false),
      policyScope: ($eff.scope // "NONE"), policyState: ($eff.state // "None"), immutabilityPeriodDays: ($eff.days // null),
      allowProtectedAppendWrites: ($eff.allowProtectedAppendWrites // null), allowProtectedAppendWritesAll: ($eff.allowProtectedAppendWritesAll // null),
      legalHold: $lh, legalHoldTags: ([($p.legalHold.tags // [])[] | .tag] | join(";")),
      versionLevelImmutability: $vl,
      wormState: $ws,
      wormCompliant: ($ws == "LOCKED_AND_RETENTION_SUFFICIENT"),
      meetsTarget: ($ws == "LOCKED_AND_RETENTION_SUFFICIENT" and (($eff.days // 0) >= $cfg.archiveTarget)),
      lastModifiedTime: ($p.lastModifiedTime // null)
    };

# ---- RBAC ----------------------------------------------------------------------------------------
def role_class:
  (.properties.permissions // []) as $perms
  | ([$perms[].actions[]?] | map(lc)) as $a
  | ([$perms[].notActions[]?] | map(lc)) as $na
  | ([$perms[].dataActions[]?] | map(lc)) as $da
  | ($a | map(select(test("^microsoft\\.support/") | not))) as $a2
  | if ($a2 | index("*")) and (($na | map(select(test("^microsoft\\.authorization/(\\*|\\*/write|roleassignments/write|\\*/delete)"))) | length) == 0) then "ADMIN"
    elif ($a2 | map(select(test("^microsoft\\.authorization/(\\*|roleassignments/\\*|roleassignments/write|\\*/write)$"))) | length) > 0 then "ADMIN"
    elif ($a2 | map(select(. == "*" or test("(/\\*|/write|/delete)$") or test("(listkeys|regeneratekey|listconnectionstrings|sharedkeys|listaccountsas|listservicesas)/action$"))) | length) > 0 then "WRITE"
    elif ($da | map(select(. == "*" or test("(/\\*|/write|/delete|/send/action|/add/action|/move/action|/runassuperuser/action)$"))) | length) > 0 then "DATA_WRITE"
    elif ($da | length) > 0 then "DATA_READ"
    else "READ" end;

# ---- misc ------------------------------------------------------------------------------------------
def la_rows: (.tables[0] // {columns: [], rows: []}) as $t | [ $t.rows[] as $r | [$t.columns, $r] | transpose | map({key: .[0].name, value: .[1]}) | from_entries ];
def worst_status: (map(.status)) as $s
  | if ($s | index("FAIL")) then "FAIL" elif ($s | index("ERROR")) then "ERROR" elif ($s | index("WARNING")) then "WARNING"
    elif ($s | index("NOT_VERIFIABLE")) then "NOT_VERIFIABLE" elif ($s | index("PASS")) then "PASS"
    elif ($s | index("NOT_APPLICABLE")) then "NOT_APPLICABLE" else "NOT_VERIFIABLE" end;
JQEOF
}

# =============================================================================
# DEPENDENCIES / INITIALIZATION
# =============================================================================
check_dependencies() {
  local ok=true v
  if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 3 ] || { [ "${BASH_VERSINFO[0]}" -eq 3 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
    echo "[ERROR] bash >= 3.2 is required" >&2; ok=false
  fi
  AZ_BIN="$(type -P az 2>/dev/null || true)"
  [ -n "$AZ_BIN" ] || { echo "[ERROR] Azure CLI 'az' not found in PATH (not installing automatically)" >&2; ok=false; }
  if ! type -P jq >/dev/null 2>&1; then
    echo "[ERROR] 'jq' not found in PATH (not installing automatically)" >&2; ok=false
  else
    v="$(jq --version 2>/dev/null | sed -E 's/^jq-//')"
    case "$v" in 1.[0-5]|1.[0-5].*) echo "[ERROR] jq >= 1.6 required (found $v)" >&2; ok=false ;; esac
  fi
  if [ -n "$CRIBL_API_URL" ] && ! type -P curl >/dev/null 2>&1; then
    echo "[ERROR] CRIBL_API_URL is set but 'curl' is not available" >&2; ok=false
  fi
  TIMEOUT_BIN="$(type -P timeout 2>/dev/null || type -P gtimeout 2>/dev/null || true)"
  [ "$ok" = true ] || exit 3
}

init_output() {
  RUN_TS="$(date -u +%Y-%m-%dT%H%M%SZ)"
  RUN_DIR="${OUTPUT_DIR%/}/$RUN_TS"
  if [ -e "$RUN_DIR" ]; then RUN_DIR="${RUN_DIR}-$$"; fi
  RAW_DIR="$RUN_DIR/raw"
  WORK="$RUN_DIR/raw/.work"
  JQLIB_DIR="$WORK/jq"
  mkdir -p "$RAW_DIR" "$WORK/tmp" "$WORK/shards/main" "$WORK/cache/cat" "$WORK/cache/principal" "$WORK/cache/roledefs" "$JQLIB_DIR" "$WORK/subs" || {
    echo "[ERROR] cannot create output directory $RUN_DIR" >&2; exit 3; }
  SHARD_DIR="$WORK/shards/main"
  LOG_FILE="$RUN_DIR/audit.log"
  : > "$LOG_FILE"
  echo '{}' > "$WORK/subnames.json"
  write_jq_lib; write_jq_lib_ext; write_report_lib
  if ! jq -n -L "$JQLIB_DIR" 'include "lib"; "ok"' >/dev/null 2>&1; then
    echo "[ERROR] internal jq library failed to compile:" >&2
    jq -n -L "$JQLIB_DIR" 'include "lib"; "ok"' >&2
    exit 3
  fi
}

get_tenant() {
  local t; t="$(tmpf)"
  if ! az_json "$t" account show; then
    log_error "Not authenticated with Azure CLI (az account show failed): $(err_msg "$t")"
    log_error "Run 'az login' (or configure a service principal / managed identity) and retry."
    exit 3
  fi
  TENANT_ID="$(jq -r '.tenantId // ""' "$t")"
  jq '{tenantId, environmentName, identityType: (.user.type // "unknown"), defaultSubscriptionId: .id}' "$t" > "$WORK/account.json"
  rm -f "$t"
  [ -n "$TENANT_ID" ] || { log_error "Could not determine tenant ID"; exit 3; }

  # Cloud endpoints (sovereign cloud support).
  t="$(tmpf)"
  if az_json "$t" cloud show; then
    ARM="$(jq -r '.endpoints.resourceManager // "https://management.azure.com/"' "$t")"
    GRAPH="$(jq -r '.endpoints.microsoftGraphResourceId // "https://graph.microsoft.com/"' "$t")"
  fi
  rm -f "$t" "$t.err"
  ARM="${ARM%/}"; GRAPH="${GRAPH%/}"; ARM_LC="$(lower "$ARM")"

  t="$(tmpf)"
  if az_json "$t" version; then
    jq '{azureCli: (.["azure-cli"] // "unknown"), azureCliCore: (.["azure-cli-core"] // "unknown")}' "$t" > "$WORK/azversion.json"
  else
    echo '{"azureCli":"unknown"}' > "$WORK/azversion.json"
  fi
  rm -f "$t" "$t.err"
  log_info "Tenant: $TENANT_ID"
  log_info "Azure CLI: $(jq -r .azureCli "$WORK/azversion.json") | jq: $(jq --version) | bash: $BASH_VERSION | parallel: $MAX_PARALLEL"
  log_info "Output: $RUN_DIR"
}

get_subscriptions() {
  local t; t="$(tmpf)"
  if ! az_json "$t" account list --all; then
    log_error "az account list failed: $(err_msg "$t")"; exit 3
  fi
  jq -c --arg tenant "$TENANT_ID" --arg only "$OPT_SUBSCRIPTIONS" --arg ex "$EXCLUDE_SUBSCRIPTIONS_REGEX" \
        --arg mg "$MANAGEMENT_SUBSCRIPTIONS_REGEX" --arg exmg "$EXCLUDE_MANAGEMENT_SUBSCRIPTIONS" '
    def rx($re): if $re == "" then false else test($re; "i") end;
    ($only | ascii_downcase | split(" ") | map(select(. != ""))) as $o
    | [ .[] | {id: (.id | ascii_downcase), name: .name, state: .state, tenantId: .tenantId}
        | .include = true | .skipReason = ""
        | if .tenantId != $tenant then .include = false | .skipReason = "other tenant (az rest tokens are issued for the current tenant)"
          elif ($o | length) > 0 and (($o | index(.id)) == null) then .include = false | .skipReason = "not selected via --subscription"
          elif .state != "Enabled" then .include = false | .skipReason = ("subscription state " + .state)
          elif ((.id | rx($ex)) or (.name | rx($ex))) then .include = false | .skipReason = "matched EXCLUDE_SUBSCRIPTIONS_REGEX"
          elif $exmg == "true" and ((.id | rx($mg)) or (.name | rx($mg))) then .include = false | .skipReason = "management subscription excluded"
          else . end
        | .isManagement = ((.id | rx($mg)) or (.name | rx($mg))) ]
    | unique_by(.id)' "$t" > "$WORK/subscriptions.json"
  rm -f "$t"
  jq 'map({key: .id, value: .name}) | from_entries' "$WORK/subscriptions.json" > "$WORK/subnames.json"
  local n_all n_inc id
  n_all="$(jq 'length' "$WORK/subscriptions.json")"
  n_inc="$(jq '[.[] | select(.include)] | length' "$WORK/subscriptions.json")"
  for id in $OPT_SUBSCRIPTIONS; do
    if [ "$(jq --arg id "$(lower "$id")" '[.[] | select(.id == $id)] | length' "$WORK/subscriptions.json")" = 0 ]; then
      log_warn "Requested subscription $id is not visible to the current identity"
      add_finding control=SUB-001 status=NOT_VERIFIABLE severity=HIGH subscriptionId="$(lower "$id")" \
        actual="Subscription not visible to identity" reason="Requested via --subscription but not returned by az account list" \
        evidence="az account list --all"
    fi
  done
  jq -r '.[] | select(.include | not) | "\(.id)\t\(.name)\t\(.skipReason)"' "$WORK/subscriptions.json" | while IFS=$'\t' read -r id name why; do
    log_verbose "Skipping subscription $name ($id): $why"
  done
  log_info "Discovered $n_all subscriptions; $n_inc enabled subscription(s) in scope"
  [ "$n_inc" -gt 0 ] || log_warn "No subscription in scope - the report will contain no resource evidence"
}

# =============================================================================
# INVENTORY (Azure Resource Graph, ARM fallback)
# =============================================================================
inventory_resources() { # <sub_id> <sub_name> -> writes $WORK/subs/<id>/resources.json
  local sub="$1" subname="$2" dir="$WORK/subs/$1" out rc kql
  mkdir -p "$dir"; out="$dir/resources.json"
  kql="resources
| project id, name, type = tolower(type), kind, location, resourceGroup, subscriptionId = tolower(subscriptionId),
          skuName = tostring(sku.name), skuTier = tostring(sku.tier), tags,
          properties = iff(tolower(type) in ('microsoft.operationalinsights/workspaces','microsoft.insights/components','microsoft.databricks/workspaces','microsoft.insights/datacollectionrules','microsoft.insights/datacollectionendpoints','microsoft.sql/servers/databases'), properties, dynamic(null))
| order by id asc"
  log_info "Discovering resources..."
  arg_query "$sub" "$kql" "$out"; rc=$?
  if [ $rc -ne 0 ]; then
    log_warn "Resource Graph query failed ($(rc_name $rc)): $(err_msg "$out") - falling back to ARM resource list"
    record_error inventory resource-graph "/subscriptions/$sub" "$(rc_name $rc)" "$(err_msg "$out")" "$sub"
    # ARM fallback: GET /subscriptions/{id}/resources (paged)
    get_all_pages "$(arm_url "/subscriptions/$sub/resources" "$API_RESOURCES")" "$out.arm"; rc=$?
    if [ $rc -ne 0 ]; then
      record_error inventory arm-resource-list "/subscriptions/$sub" "$(rc_name $rc)" "$(err_msg "$out.arm")" "$sub"
      return $rc
    fi
    jq '[.[] | {id, name, type: (.type | ascii_downcase), kind: (.kind // null), location: (.location // null),
               resourceGroup: ((.id | capture("/resourceGroups/(?<rg>[^/]+)"; "i").rg) // ""),
               subscriptionId: ((.id | capture("^/subscriptions/(?<s>[^/]+)"; "i").s | ascii_downcase) // ""),
               skuName: (.sku.name // ""), skuTier: (.sku.tier // ""), tags: (.tags // {}), properties: null}]' "$out.arm" > "$out"
    rm -f "$out.arm"
  fi
  # Redact secret-like properties (e.g. App Insights ConnectionString) before anything is persisted.
  if ! jqlib 'redact' "$out" > "$out.red" 2>/dev/null; then
    record_error inventory redact "/subscriptions/$sub" ERROR "inventory JSON could not be processed" "$sub"; rm -f "$out" "$out.red"; return $RC_ERROR
  fi
  mv -f "$out.red" "$out"
  jq -c --arg sn "$subname" '.[] | . + {subscriptionName: $sn}' "$out" >> "$SHARD_DIR/resources.jsonl"
  log_info "Found $(jq length "$out") resources"
  return 0
}

by_type() { # <sub_id> <type-regex> -> JSON lines of matching resources
  jq -c --arg re "$2" '.[] | select(.type | test($re; "i"))' "$WORK/subs/$1/resources.json" 2>/dev/null
}

# =============================================================================
# SUBSCRIPTION ACTIVITY LOG
# API: GET /subscriptions/{id}/providers/Microsoft.Insights/diagnosticSettings
#      GET /subscriptions/{id}/providers/Microsoft.Insights/diagnosticSettingsCategories
# =============================================================================
audit_subscription_activity_logs() { # <sub> <subname>
  local sub="$1" subname="$2" t c rc rcc ev
  t="$(tmpf)"; c="$(tmpf)"
  log_info "Auditing subscription Activity Log export..."
  get_all_pages "$(arm_url "/subscriptions/$sub/providers/Microsoft.Insights/diagnosticSettings" "$API_DIAG")" "$t"; rc=$?
  get_all_pages "$(arm_url "/subscriptions/$sub/providers/Microsoft.Insights/diagnosticSettingsCategories" "$API_DIAG")" "$c"; rcc=$?
  [ $rcc -eq 0 ] || echo '[]' > "$c"
  if [ $rc -ne 0 ]; then
    record_error activity-log diagnosticSettings "/subscriptions/$sub" "$(rc_name $rc)" "$(err_msg "$t")" "$sub"
    emit activity "$(jq -nc --arg s "$sub" --arg n "$subname" --arg st "$(rc_name $rc)" --arg e "$(err_msg "$t")" \
       '{subscriptionId: $s, subscriptionName: $n, auditStatus: $st, auditError: $e}')"
    add_finding control=ACT-001 status="$(rc_status $rc)" severity=HIGH subscriptionId="$sub" \
      resourceId="/subscriptions/$sub" resourceType="microsoft.resources/subscriptions" resourceName="$subname" \
      actual="Subscription diagnostic settings not readable" reason="$(rc_name $rc): $(err_msg "$t")" \
      evidence="GET /subscriptions/$sub/providers/Microsoft.Insights/diagnosticSettings?api-version=$API_DIAG"
    rm -f "$t" "$t.err" "$c" "$c.err"; return
  fi
  ev="$(save_raw activity-log "/subscriptions/$sub" "$t")"
  local rec; rec="$(tmpf)"
  jqlib '
    ($cats[0] | map(select(((.properties.categoryType // "Logs") | lc) == "logs") | .name)) as $avail0
    | (if ($avail0 | length) > 0 then $avail0 else ($expected | split(" ")) end) as $avail
    | ($avail | map({key: lc, value: []}) | from_entries) as $groupsOf
    | settings_eval($avail; $groupsOf) as $S
    | ($required | split(" ") | map(select(. != ""))) as $req
    | ($expected | split(" ") | map(select(. != ""))) as $exp
    | ([$S[] | select(.workspaceId != null) | .enabledCategories[]] | unique) as $toLaw
    | ([$S[] | select(.storageAccountId != null) | .enabledCategories[]] | unique) as $toSto
    | ([$S[] | select(.eventHubAuthorizationRuleId != null) | .enabledCategories[]] | unique) as $toEh
    | {
        subscriptionId: $sub, subscriptionName: $subname, auditStatus: "OK", auditError: "",
        availableCategories: $avail, settingsCount: ($S | length), settings: $S, settingsSummary: ($S | settings_summary),
        enabledCategories: ([$S[].enabledCategories[]] | unique),
        categoriesToLaw: $toLaw, categoriesToStorage: $toSto, categoriesToEventHub: $toEh,
        requiredCategories: $req, expectedCategories: $exp,
        requiredNotToLaw: [$req[] | select(. as $x | ($toLaw | map(lc) | index($x | lc)) | not)],
        requiredNotToStorage: [$req[] | select(. as $x | ($toSto | map(lc) | index($x | lc)) | not)],
        requiredNotToEventHub: [$req[] | select(. as $x | ($toEh | map(lc) | index($x | lc)) | not)],
        expectedMissing: [$exp[] | select(. as $x | ($avail | map(lc) | index($x | lc))) | select(. as $x | ([$S[].enabledCategories[]] | map(lc) | index($x | lc)) | not)],
        workspaces: ([$S[].workspaceId | select(. != null) | lc] | unique),
        storageAccounts: ([$S[].storageAccountId | select(. != null) | lc] | unique),
        eventHubNamespaces: ([$S[].eventHubNamespaceId | select(. != null) | lc] | unique),
        eventHubNames: ([$S[].eventHubName | select(. != null)] | unique),
        evidenceFile: $ev
      }' -c --arg sub "$sub" --arg subname "$subname" --arg ev "$ev" \
         --arg required "$ACTIVITY_REQUIRED_CATEGORIES" --arg expected "$ACTIVITY_EXPECTED_CATEGORIES" \
         --slurpfile cats "$c" "$t" > "$rec"
  emit_file activity "$rec"
  local f; f="$(tmpf)"
  jqlib '
    . as $r
    | {subscriptionId: $r.subscriptionId, resourceId: ("/subscriptions/" + $r.subscriptionId), resourceType: "microsoft.resources/subscriptions",
       resourceName: $r.subscriptionName, evidenceFile: $r.evidenceFile} as $b
    | ("GET /subscriptions/" + $r.subscriptionId + "/providers/Microsoft.Insights/diagnosticSettings?api-version=" + $api) as $how
    | ( if $r.settingsCount == 0 then
          $b + {control: "ACT-001", status: "FAIL", severity: "CRITICAL", expected: ("Activity Log categories " + ($r.requiredCategories | join(", ")) + " exported to LAW + immutable storage"),
                actual: "No subscription diagnostic setting: Activity Log is only retained by the platform for 90 days",
                evidence: ($how + " returned 0 settings"), reason: "Control-plane audit trail has no durable destination.",
                recommendation: "Create a subscription diagnostic setting exporting Administrative, Security, Policy (and the other categories) to the central LAW and the immutable archive."}
        elif ($r.requiredNotToLaw | length) == 0 then
          $b + {control: "ACT-001", status: "PASS", actual: ("Required categories to LAW: " + ($r.workspaces | map(name_of) | join(", "))), evidence: ($how + " | " + $r.settingsSummary)}
        else
          $b + {control: "ACT-001", status: "FAIL", severity: "HIGH", expected: ("Categories " + ($r.requiredCategories | join(", ")) + " exported to LAW"),
                actual: ("Not exported to LAW: " + ($r.requiredNotToLaw | join(", ")) + " | settings: " + $r.settingsSummary),
                evidence: $how, reason: "Subscription Activity Logs are not centrally collected.",
                recommendation: "Add the central LAW as destination for all required Activity Log categories."}
        end ),
      ( if $r.settingsCount == 0 then empty
        elif ($r.expectedMissing | length) == 0 then $b + {control: "ACT-004", status: "PASS", actual: ("Enabled: " + ($r.enabledCategories | join(", "))), evidence: $how}
        else $b + {control: "ACT-004", status: "WARNING", severity: "LOW", expected: ("All categories: " + ($r.expectedCategories | join(", "))),
                   actual: ("Not exported: " + ($r.expectedMissing | join(", "))), evidence: $how,
                   recommendation: "Enable the remaining Activity Log categories."}
        end )' -c --arg api "$API_DIAG" "$rec" > "$f"
  ingest_findings "$f"
  rm -f "$t" "$c" "$rec" "$f" "$t.err" "$c.err"
}

# =============================================================================
# RESOURCE DIAGNOSTIC SETTINGS
# API: GET {resourceId}/providers/Microsoft.Insights/diagnosticSettingsCategories
#      GET {resourceId}/providers/Microsoft.Insights/diagnosticSettings
# Categories are discovered from Azure (never hard-coded) and cached per
# (type, kind, sku) to avoid N x M calls; a cache miss re-queries per resource.
# =============================================================================
cat_cache_file() { # <resource json line>
  local key; key="$(printf '%s' "$1" | jq -r '[.type, (.kind // ""), (.skuName // "")] | join("|") | ascii_downcase')"
  printf '%s/cache/cat/%s' "$WORK" "$(safe_name "$key")"
}

# fetch_categories <resource json line> <out file> ; returns rc and fills cache
fetch_categories() {
  local r="$1" out="$2" id cache rc
  id="$(printf '%s' "$r" | jq -r .id)"
  cache="$(cat_cache_file "$r")"
  if [ -s "$cache.json" ]; then cp "$cache.json" "$out"; return $RC_OK; fi
  if [ -e "$cache.unsupported" ]; then return $RC_UNSUPPORTED; fi
  get_all_pages "$(arm_url "$id/providers/Microsoft.Insights/diagnosticSettingsCategories" "$API_DIAG")" "$out"; rc=$?
  if [ $rc -eq 0 ]; then
    if [ "$(jq 'length' "$out")" = 0 ]; then
      : > "$cache.unsupported.$$" && mv -f "$cache.unsupported.$$" "$cache.unsupported"; return $RC_UNSUPPORTED
    fi
    cp "$out" "$cache.json.$$" && mv -f "$cache.json.$$" "$cache.json"
    return $RC_OK
  fi
  if [ $rc -eq $RC_UNSUPPORTED ] || { [ $rc -eq $RC_BADREQUEST ] && grep -Eiq 'not support' "$out.err" 2>/dev/null; }; then
    : > "$cache.unsupported.$$" && mv -f "$cache.unsupported.$$" "$cache.unsupported"; return $RC_UNSUPPORTED
  fi
  return $rc
}

prewarm_category() { # <resource json line>
  local t; t="$(tmpf)"; fetch_categories "$1" "$t" >/dev/null 2>&1; rm -f "$t" "$t.err"
}

audit_resource_diag() { # <resource json line>
  local r="$1" id cats settings rc ev bundle rec f status err
  id="$(printf '%s' "$r" | jq -r .id)"
  cats="$(tmpf)"; settings="$(tmpf)"; bundle="$(tmpf)"; rec="$(tmpf)"; f="$(tmpf)"
  status=OK; err=""
  fetch_categories "$r" "$cats"; rc=$?
  if [ $rc -eq $RC_UNSUPPORTED ]; then
    status=UNSUPPORTED; echo '[]' > "$cats"
  elif [ $rc -ne 0 ]; then
    status="$(rc_name $rc)"; err="$(err_msg "$cats")"; echo '[]' > "$cats"
    record_error diagnostic-settings categories "$id" "$status" "$err"
  fi
  echo '[]' > "$settings"
  if [ "$status" = OK ]; then
    get_all_pages "$(arm_url "$id/providers/Microsoft.Insights/diagnosticSettings" "$API_DIAG")" "$settings"; rc=$?
    if [ $rc -ne 0 ]; then
      if [ $rc -eq $RC_UNSUPPORTED ]; then status=UNSUPPORTED
      else status="$(rc_name $rc)"; err="$(err_msg "$settings")"; record_error diagnostic-settings list "$id" "$status" "$err"; fi
      echo '[]' > "$settings"
    else
      ev="$(save_raw diagnostic-settings "$id" "$settings")"
    fi
  fi
  jq -n --argjson res "$r" --slurpfile c "$cats" --slurpfile st "$settings" --arg ev "${ev:-}" \
     '{resource: ($res + {evidenceFile: $ev}), categories: $c[0], settings: $st[0]}' > "$bundle"
  jqlib 'diag_eval($cfg) | .auditStatus = $status | .auditError = $err
         | if $status == "UNSUPPORTED" then .supported = false | .coverage = "NOT_SUPPORTED"
           elif $status != "OK" then .coverage = "UNABLE_TO_AUDIT" else . end' -c \
     --argjson cfg "$DIAG_CFG" --arg status "$status" --arg err "$err" "$bundle" > "$rec"
  emit_file diagnostic "$rec"
  jqlib 'diag_findings($cfg)' -c --argjson cfg "$DIAG_CFG" "$rec" > "$f"
  ingest_findings "$f"
  rm -f "$cats" "$settings" "$bundle" "$rec" "$f" "$cats.err" "$settings.err"
}

audit_skipped_resource() { # <resource json line> -> record only
  printf '%s' "$1" | jq -c '{id, name, type, kind, location, resourceGroup, subscriptionId, subscriptionName,
     auditStatus: "SKIPPED", auditError: "type matches DIAG_SKIP_TYPES_REGEX", supported: false, coverage: "SKIPPED_BY_CONFIG",
     logCategories: [], settingsCount: 0}' >> "$SHARD_DIR/diagnostic.jsonl"
}

build_diag_cfg() {
  DIAG_CFG="$(jq -nc --arg requiredMode "$REQUIRED_CATEGORIES_MODE" --arg requiredCategoryRegex "$REQUIRED_CATEGORY_REGEX" \
     --arg prodRegex "$PROD_REGEX" --arg criticalTypesRegex "$CRITICAL_TYPES_REGEX" --arg centralLawRegex "$CENTRAL_LAW_REGEX" \
     --arg archivePolicy "$RESOURCE_ARCHIVE_POLICY" --arg ehPolicy "$RESOURCE_EVENTHUB_POLICY" \
     --arg dedicatedRegex "$DEDICATED_CAPABLE_TYPES_REGEX" --arg apiDiag "$API_DIAG" \
     '{requiredMode: $requiredMode, requiredCategoryRegex: $requiredCategoryRegex, prodRegex: $prodRegex,
       criticalTypesRegex: $criticalTypesRegex, centralLawRegex: $centralLawRegex, archivePolicy: $archivePolicy,
       ehPolicy: $ehPolicy, dedicatedRegex: $dedicatedRegex, apiDiag: $apiDiag}')"
}

audit_diagnostic_settings() { # <sub> <subname>
  local sub="$1" subname="$2" dir="$WORK/subs/$1" targets line n=0 total
  targets="$dir/diag-targets.jsonl"
  # Targets = inventory resources + storage sub-services (blob/file/queue/table
  # diagnostic settings live on child resources, not on the storage account).
  jq -c --arg svcs "$STORAGE_DIAG_SERVICES" --arg sn "$subname" '
      .[] | . + {subscriptionName: $sn}
      | ., (if .type == "microsoft.storage/storageaccounts" then
              . as $sa | ($svcs | split(" ") | map(select(. != "")))[] as $s
              | $sa + {id: ($sa.id + "/" + $s + "Services/default"), name: ($sa.name + "/" + $s),
                       type: ("microsoft.storage/storageaccounts/" + $s + "services"), parentId: $sa.id}
            else empty end)' "$dir/resources.json" > "$targets"
  jqlib 'select(.type | rx($skip))' -c --arg skip "$DIAG_SKIP_TYPES_REGEX" "$targets" > "$dir/diag-skip.jsonl"
  jqlib 'select(.type | rx($skip) | not)' -c --arg skip "$DIAG_SKIP_TYPES_REGEX" "$targets" > "$dir/diag-audit.jsonl"
  total="$(wc -l < "$dir/diag-audit.jsonl" | tr -d ' ')"
  log_info "Auditing diagnostic settings on $total resource scopes ($(wc -l < "$dir/diag-skip.jsonl" | tr -d ' ') skipped by DIAG_SKIP_TYPES_REGEX)..."
  while IFS= read -r line; do audit_skipped_resource "$line"; done < "$dir/diag-skip.jsonl"

  # 1) Pre-warm the category cache with one representative per (type, kind, sku).
  while IFS= read -r line; do
    pool_run prewarm_category "$line"
  done < <(jq -sc 'group_by([.type, (.kind // ""), (.skuName // "")] | map(ascii_downcase)) | .[] | .[0]' "$dir/diag-audit.jsonl")
  pool_wait

  # 2) Audit every resource.
  while IFS= read -r line; do
    n=$((n + 1))
    if [ $((n % 200)) -eq 0 ]; then log_info "  ... $n/$total"; fi
    pool_run audit_resource_diag "$line"
  done < "$dir/diag-audit.jsonl"
  pool_wait
}

# =============================================================================
# JQ LIBRARY EXTENSION: LAW tables / exports
# =============================================================================
write_jq_lib_ext() {
  cat >> "$JQLIB_DIR/lib.jq" <<'JQEOF'

def export_rules:
  map((.properties.destination.resourceId // "") as $d
      | { name: (.name // ""), id: (.id // ""), enabled: (.properties.enable // false),
          tables: (.properties.tableNames // []),
          destinationId: ($d | lc),
          destinationType: ((.properties.destination.type // "") as $ty
                            | if $ty != "" then $ty
                              elif ($d | test("/microsoft\\.eventhub/namespaces/"; "i")) then "EventHub"
                              elif ($d | test("/microsoft\\.storage/storageaccounts/"; "i")) then "StorageAccount"
                              else "Unknown" end),
          eventHubName: (.properties.destination.metaData.eventHubName // null),
          createdDate: (.properties.createdDate // null), lastModifiedDate: (.properties.lastModifiedDate // null) });

def law_tables_eval($cfg; $supported):
  . as $B
  | ($B.ws.properties.retentionInDays // null) as $wsRet
  | (if $B.usageStatus == "OK" then ($B.usage | map({key: ((.DataType // "") | lc), value: .}) | from_entries) else null end) as $act
  | ($B.exports | export_rules) as $rules
  | ([$rules[] | select(.enabled and .destinationType == "EventHub") | .tables[] | lc] | unique) as $expEh
  | ([$rules[] | select(.enabled and .destinationType == "StorageAccount") | .tables[] | lc] | unique) as $expSto
  | [ $B.tables[] | (.properties // {}) as $p | (.name // "") as $n | ($n | lc) as $nl
      | { workspaceId: ($B.resource.id | lc), workspaceName: $B.resource.name, subscriptionId: ($B.resource.subscriptionId | lc),
          table: $n, plan: ($p.plan // "Analytics"), tableType: ($p.schema.tableType // ""), tableSubType: ($p.schema.tableSubType // ""),
          retentionInDays: ($p.retentionInDays // $wsRet),
          retentionInherited: (if $p.retentionInDaysAsDefault != null then $p.retentionInDaysAsDefault else ($p.retentionInDays == null) end),
          totalRetentionInDays: ($p.totalRetentionInDays // null),
          totalRetentionInherited: ($p.totalRetentionInDaysAsDefault // null),
          archiveRetentionInDays: ($p.archiveRetentionInDays // null),
          provisioningState: ($p.provisioningState // ""),
          active: (if $act == null then null else ($act[$nl] != null) end),
          lastSeen: (if $act == null then null else ($act[$nl].LastSeen // null) end),
          volumeMB: (if $act == null then null else ($act[$nl].VolumeMB // null) end),
          class: (if ($n | rx($cfg.exemptRegex)) then "EXEMPT" elif ($n | rx($cfg.debugRegex)) then "DEBUG" else "SECURITY_AUDIT_OPERATIONAL" end),
          customColumns: (if ($n | endswith("_CL")) then [($p.schema.columns // [])[] | .name] else [] end),
          exportedToEventHub: (($expEh | index($nl)) != null),
          exportedToStorage: (($expSto | index($nl)) != null),
          exportRules: [$rules[] | select(.tables | map(lc) | index($nl)) | .name + (if .enabled then "" else "(disabled)" end)] }
      | . + ( if (.tableType | test("^(RestoredLogs|SearchResults)$"; "i")) then
                {exportEligibility: "UNSUPPORTED", eligibilityReason: "Restored / search-results tables are not exported by Data Export"}
              elif (((.plan | lc) as $pl | ($cfg.unsupportedPlans | map(lc) | index($pl))) != null) then
                {exportEligibility: "UNSUPPORTED", eligibilityReason: ("Table plan " + .plan + " listed in EXPORT_UNSUPPORTED_PLANS")}
              elif (.table | rx($cfg.exportUnsupportedRegex)) then
                {exportEligibility: "UNSUPPORTED", eligibilityReason: "Matches EXPORT_UNSUPPORTED_TABLE_REGEX"}
              elif $supported != null then
                (if (.table | endswith("_CL")) or (($supported | index($nl)) != null)
                 then {exportEligibility: "ELIGIBLE", eligibilityReason: "Custom table or listed in EXPORT_SUPPORTED_TABLES_FILE"}
                 else {exportEligibility: "UNSUPPORTED", eligibilityReason: "Not listed in EXPORT_SUPPORTED_TABLES_FILE"} end)
              else
                {exportEligibility: "ELIGIBLE_UNCONFIRMED", eligibilityReason: "Structurally eligible; Microsoft's supported-table list is not exposed by an API (set EXPORT_SUPPORTED_TABLES_FILE for an authoritative result)"}
              end ) ];

def law_record($cfg; $tables):
  . as $B | ($B.ws.properties // {}) as $p
  | ($B.exports | export_rules) as $rules
  | ($B.usageStatus == "OK" and $B.tablesStatus == "OK") as $actKnown
  | ($tables | map(select(.active == true))) as $activeT
  | ([$tables[].table | lc]) as $allNames
  | ([$rules[] | select(.enabled and .destinationType == "EventHub") | .tables[]] | unique) as $expEh
  | {
      id: ($B.resource.id | lc), name: $B.resource.name, subscriptionId: ($B.resource.subscriptionId | lc),
      subscriptionName: ($B.resource.subscriptionName // ""), resourceGroup: ($B.resource.resourceGroup // ($B.resource.id | rg_of)),
      location: ($B.ws.location // $B.resource.location // ""),
      customerId: ($p.customerId // ""), sku: ($p.sku.name // ""), retentionInDays: ($p.retentionInDays // null),
      dailyQuotaGb: ($p.workspaceCapping.dailyQuotaGb // null), dataIngestionStatus: ($p.workspaceCapping.dataIngestionStatus // null),
      publicNetworkAccessForIngestion: ($p.publicNetworkAccessForIngestion // null), publicNetworkAccessForQuery: ($p.publicNetworkAccessForQuery // null),
      disableLocalAuth: ($p.features.disableLocalAuth // false),
      resourcePermissionsOnly: ($p.features.enableLogAccessUsingOnlyResourcePermissions // null),
      provisioningState: ($p.provisioningState // ""), excluded: ($B.resource.name | rx($cfg.lawExcludeRegex)),
      auditStatus: "OK", auditError: "",
      tablesStatus: $B.tablesStatus, tablesError: $B.tablesError, usageStatus: $B.usageStatus, usageError: $B.usageError,
      exportsStatus: $B.exportsStatus, exportsError: $B.exportsError,
      lawTablesCount: ($tables | length), activeTablesKnown: $actKnown,
      activeTablesCount: (if $actKnown then ($activeT | length) else null end),
      activeTables: [$activeT[].table],
      exportableActive: [$activeT[] | select(.exportEligibility != "UNSUPPORTED") | .table],
      exportedToEventHub: $expEh,
      exportedToStorage: ([$rules[] | select(.enabled and .destinationType == "StorageAccount") | .tables[]] | unique),
      missingExports: [$activeT[] | select(.exportEligibility == "ELIGIBLE" and (.exportedToEventHub | not)) | .table],
      missingExportsUnconfirmed: [$activeT[] | select(.exportEligibility == "ELIGIBLE_UNCONFIRMED" and (.exportedToEventHub | not)) | .table],
      unsupportedActive: [$activeT[] | select(.exportEligibility == "UNSUPPORTED") | .table],
      unsupportedTablesCount: ([$tables[] | select(.exportEligibility == "UNSUPPORTED")] | length),
      exportedNonexistent: (if $B.tablesStatus == "OK" then [$expEh[] | select(. as $x | ($allNames | index($x | lc)) == null)] else [] end),
      exportRulesCount: ($rules | length),
      enabledEventHubRules: ([$rules[] | select(.enabled and .destinationType == "EventHub")] | length),
      exportRules: $rules,
      eventHubDestinations: [$rules[] | select(.enabled and .destinationType == "EventHub") | {rule: .name, namespaceId: .destinationId, eventHubName, tables}],
      storageDestinations: [$rules[] | select(.enabled and .destinationType == "StorageAccount") | {rule: .name, storageAccountId: .destinationId, tables}],
      azureDiagnosticsActive: (if $actKnown then (([$activeT[].table] | index("AzureDiagnostics")) != null) else null end),
      azureDiagnosticsProviders: ($B.azdiag // []),
      customLogTables: [$tables[] | select(.table | endswith("_CL")) | .table],
      activeAppTables: [$activeT[] | select(.table | startswith("App")) | .table],
      evidenceFile: ($B.evidenceFile // "")
    };

def law_findings($cfg; $tables):
  . as $L
  | {subscriptionId: $L.subscriptionId, resourceId: $L.id, resourceType: "microsoft.operationalinsights/workspaces",
     resourceName: $L.name, evidenceFile: $L.evidenceFile} as $b
  | ("GET " + $L.id + "?api-version=" + $cfg.apiLaw) as $how
  # LAW-001 workspace default retention
  | ( if $L.retentionInDays == null then
        $b + {control: "LAW-001", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: "retentionInDays not returned", evidence: $how}
      elif $L.retentionInDays >= $cfg.hotMin then
        $b + {control: "LAW-001", status: "PASS", expected: (">= " + ($cfg.hotMin | tostring) + " days"), actual: (($L.retentionInDays | tostring) + " days"), evidence: $how}
      else
        $b + {control: "LAW-001", status: "FAIL", severity: "MEDIUM", expected: (">= " + ($cfg.hotMin | tostring) + " days interactive retention (18-24 months)"),
              actual: ("Workspace default retention " + ($L.retentionInDays | tostring) + " days"), evidence: ($how + " -> properties.retentionInDays"),
              reason: "Default retention applies to every table without an explicit override.",
              recommendation: ("Set workspace retention to " + ($cfg.hotMin | tostring) + "-" + ($cfg.hotMax | tostring) + " days, keep debug tables at <= " + ($cfg.debugMax | tostring) + " days via table-level retention.")}
      end ),
    # LAW-002 table-level retention
    ( ("GET " + $L.id + "/tables?api-version=" + $cfg.apiLaw) as $thow
      | if $L.tablesStatus == "SKIPPED" then
          $b + {control: "LAW-002", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: "Table analysis skipped (--skip-table-analysis)"}
        elif $L.tablesStatus != "OK" then
          $b + {control: "LAW-002", status: (if $L.tablesStatus == "FORBIDDEN" or $L.tablesStatus == "AUTH" then "NOT_VERIFIABLE" else "ERROR" end), severity: "MEDIUM",
                reason: ("Tables API: " + $L.tablesStatus + " " + ($L.tablesError // "")), evidence: $thow}
        else
          ( if $L.activeTablesKnown then [ $tables[] | select(.active == true or .retentionInherited == false) ]
            else [ $tables[] | select(.retentionInherited == false or (.table | rx($cfg.securityTableRegex))) ] end ) as $ev
          | ( if ($L.activeTablesKnown | not) then
                $b + {control: "LAW-002", status: "NOT_VERIFIABLE", severity: "LOW", resourceName: ($L.name + " (table activity)"),
                      reason: ("Table activity unknown (Usage query: " + $L.usageStatus + " " + ($L.usageError // "") + "); only tables with explicit retention or matching SECURITY_TABLE_REGEX were evaluated (" + ($ev | length | tostring) + " of " + ($tables | length | tostring) + ")."),
                      evidence: $thow}
              else empty end ),
            ( $ev[] | . as $t
              | ($b + {resourceName: ($L.name + "/" + $t.table), resourceId: ($L.id + "/tables/" + $t.table), resourceType: "microsoft.operationalinsights/workspaces/tables",
                       evidence: ($thow + " -> " + $t.table + ": plan=" + $t.plan + ", retentionInDays=" + ($t.retentionInDays | tostring)
                                  + (if $t.retentionInherited then " (inherited from workspace)" else " (table override)" end)
                                  + ", totalRetentionInDays=" + ($t.totalRetentionInDays | tostring)
                                  + (if $t.active == true then ", active (last seen " + ($t.lastSeen // "?" | tostring) + ")" else "" end))}) as $tb
              | if $t.class == "EXEMPT" then $tb + {control: "LAW-002", status: "NOT_APPLICABLE", reason: "Matches HOT_RETENTION_EXEMPT_TABLE_REGEX"}
                elif $t.class == "DEBUG" then
                  (if ($t.retentionInDays // 0) <= $cfg.debugMax then $tb + {control: "LAW-002", status: "PASS", expected: ("debug table <= " + ($cfg.debugMax | tostring) + " days"), actual: (($t.retentionInDays | tostring) + " days")}
                   else $tb + {control: "LAW-002", status: "FAIL", severity: "LOW", expected: ("debug/diagnostic table <= " + ($cfg.debugMax | tostring) + " days"),
                               actual: (($t.retentionInDays | tostring) + " days"), reason: "Table classified as debug/diagnostic via DEBUG_TABLE_REGEX.",
                               recommendation: ("Set table retention to <= " + ($cfg.debugMax | tostring) + " days.")} end)
                elif ($t.plan | lc) != "analytics" then
                  $tb + {control: "LAW-002", status: "FAIL", severity: "MEDIUM", expected: (">= " + ($cfg.hotMin | tostring) + " days searchable (hot) retention"),
                         actual: ("Table plan " + $t.plan + ": interactive retention " + ($t.retentionInDays | tostring) + " days, total " + ($t.totalRetentionInDays | tostring) + " days"),
                         reason: "Basic/Auxiliary plans only provide short interactive retention; long-term retention is not hot/searchable.",
                         recommendation: "Use the Analytics plan for security/audit tables or classify the table explicitly as debug/exempt."}
                elif ($t.retentionInDays // 0) >= $cfg.hotMin then
                  $tb + {control: "LAW-002", status: "PASS", expected: (">= " + ($cfg.hotMin | tostring) + " days"), actual: (($t.retentionInDays | tostring) + " days")}
                else
                  $tb + {control: "LAW-002", status: "FAIL", severity: "MEDIUM", expected: (">= " + ($cfg.hotMin | tostring) + " days hot retention"),
                         actual: (($t.retentionInDays | tostring) + " days" + (if $t.retentionInherited then " (inherited)" else " (table override)" end)),
                         reason: "Security/audit/operational table below the hot retention threshold.",
                         recommendation: ("az monitor log-analytics workspace table update --retention-time " + ($cfg.hotMin | tostring) + " (REMEDIATION EXAMPLE - NOT EXECUTED)")}
                end )
        end ),
    # LAW-003 data export to Event Hub
    ( ("GET " + $L.id + "/dataExports?api-version=" + $cfg.apiExport) as $ehow
      | if $L.excluded then $b + {control: "LAW-003", status: "NOT_APPLICABLE", reason: "Workspace excluded via LAW_EXCLUDE_REGEX"}
        elif $L.exportsStatus != "OK" then
          $b + {control: "LAW-003", status: (if $L.exportsStatus == "FORBIDDEN" or $L.exportsStatus == "AUTH" then "NOT_VERIFIABLE" else "ERROR" end), severity: "HIGH",
                reason: ("Data Export API: " + $L.exportsStatus + " " + ($L.exportsError // "")), evidence: $ehow}
        elif $L.enabledEventHubRules > 0 then
          $b + {control: "LAW-003", status: "PASS", actual: ($L.eventHubDestinations | map(.rule + " -> " + (.namespaceId | name_of) + "/" + (.eventHubName // "(per-table am-* hubs)") + " [" + (.tables | length | tostring) + " tables]") | join("; ")), evidence: $ehow}
        else
          $b + {control: "LAW-003", status: "FAIL", severity: "HIGH", expected: "At least one enabled Data Export rule with an Event Hub destination",
                actual: (if $L.exportRulesCount == 0 then "No Data Export rules"
                         else ("Rules present but none enabled towards Event Hub: " + ($L.exportRules | map(.name + "(" + .destinationType + ", enabled=" + (.enabled | tostring) + ")") | join(", "))) end),
                evidence: $ehow, reason: "LAW data is not forwarded to Cribl/SOC via Event Hub.",
                recommendation: "Create a Data Export rule to the security Event Hub namespace for all exportable active tables."}
        end ),
    # LAW-004 export coverage
    ( if $L.excluded then empty
      elif $L.exportsStatus != "OK" then empty
      elif $L.tablesStatus != "OK" or ($L.activeTablesKnown | not) then
        $b + {control: "LAW-004", status: "NOT_VERIFIABLE", severity: "MEDIUM",
              reason: ("Cannot compute MISSING_EXPORTS: tables=" + $L.tablesStatus + ", usage=" + $L.usageStatus + ". Exported to Event Hub: " + ($L.exportedToEventHub | join(", "))),
              evidence: "LAW_TABLES from /tables, ACTIVE from Usage table, EXPORTED from enabled Event Hub export rules"}
      elif ($L.activeTables | length) == 0 then
        $b + {control: "LAW-004", status: "NOT_APPLICABLE", reason: ("No table ingested data in the last " + ($cfg.lookback | tostring) + " days")}
      elif ($L.missingExports | length) > 0 then
        $b + {control: "LAW-004", status: "FAIL", severity: "MEDIUM",
              expected: "MISSING_EXPORTS = EXPORTABLE_ACTIVE - EXPORTED = {}",
              actual: ("Not exported (" + ($L.missingExports | length | tostring) + "): " + ($L.missingExports | join(", "))
                       + (if ($L.missingExportsUnconfirmed | length) > 0 then " | eligibility unconfirmed: " + ($L.missingExportsUnconfirmed | join(", ")) else "" end)),
              evidence: ("ACTIVE=" + ($L.activeTables | length | tostring) + " EXPORTED_TO_EH=" + ($L.exportedToEventHub | length | tostring) + " UNSUPPORTED_ACTIVE=" + ($L.unsupportedActive | length | tostring)),
              recommendation: "Add the missing tables to the Event Hub export rule (max 10 enabled rules per workspace)."}
      elif ($L.missingExportsUnconfirmed | length) > 0 then
        $b + {control: "LAW-004", status: "WARNING", severity: "MEDIUM",
              expected: "Every exportable active table exported to Event Hub",
              actual: ("Active tables not exported (" + ($L.missingExportsUnconfirmed | length | tostring) + "): " + ($L.missingExportsUnconfirmed | join(", "))),
              reason: "Tables are definitely not exported; whether Azure Monitor Data Export supports each of them cannot be proven from the API (no supported-table API). Provide EXPORT_SUPPORTED_TABLES_FILE for a PASS/FAIL result.",
              evidence: ("ACTIVE=" + ($L.activeTables | length | tostring) + " EXPORTED_TO_EH=" + ($L.exportedToEventHub | length | tostring)),
              recommendation: "Add these tables to the Event Hub export rule or document why they are out of scope."}
      else
        $b + {control: "LAW-004", status: "PASS", actual: ("All " + ($L.exportableActive | length | tostring) + " exportable active tables exported to Event Hub"),
              evidence: ("EXPORTED_TO_EH=" + ($L.exportedToEventHub | join(", ")))}
      end ),
    ( if ($L.exportedNonexistent | length) > 0 then
        $b + {control: "LAW-004", status: "WARNING", severity: "LOW", resourceName: ($L.name + " (export rule table names)"),
              actual: ("Export rules reference tables not present in the workspace schema: " + ($L.exportedNonexistent | join(", "))),
              recommendation: "Remove or correct stale table names in export rules."}
      else empty end ),
    # LAW-005 active tables that cannot be exported
    ( if ($L.unsupportedActive | length) > 0 then
        $b + {control: "LAW-005", status: "WARNING", severity: "MEDIUM", expected: "All security-relevant active tables can reach the Event Hub pipeline",
              actual: ("Active tables not exportable by Data Export: " + ($L.unsupportedActive | join(", "))),
              reason: "UNSUPPORTED_EXPORTS = ACTIVE - EXPORTABLE. These tables need another path (diagnostic setting to Event Hub, DCR, or plan change).",
              recommendation: "Provide an alternative streaming path for these tables."}
      else empty end ),
    # LAW-006 daily cap
    ( if ($L.dailyQuotaGb != null) and ($L.dailyQuotaGb >= 0) then
        $b + {control: "LAW-006", status: "WARNING", severity: "MEDIUM", expected: "No daily cap on security workspaces (-1)",
              actual: ("Daily cap " + ($L.dailyQuotaGb | tostring) + " GB, ingestion status " + ($L.dataIngestionStatus // "unknown" | tostring)),
              reason: "When the cap is reached, security telemetry is dropped until the next reset.", evidence: ($how + " -> workspaceCapping")}
      else $b + {control: "LAW-006", status: "PASS", actual: "No daily cap", evidence: $how} end ),
    # LAW-007 network / local auth
    ( ([ (if ($L.publicNetworkAccessForIngestion // "Enabled") == "Enabled" then "public ingestion enabled" else empty end),
         (if ($L.publicNetworkAccessForQuery // "Enabled") == "Enabled" then "public query enabled" else empty end),
         (if ($L.disableLocalAuth | not) then "local (shared key) authentication enabled" else empty end) ]) as $iss
      | if ($iss | length) > 0 then $b + {control: "LAW-007", status: "WARNING", severity: "LOW", actual: ($iss | join(", ")), evidence: $how,
                                          recommendation: "Use AMPLS/private link and disable local authentication where feasible."}
        else $b + {control: "LAW-007", status: "PASS", actual: "Public access disabled, local auth disabled", evidence: $how} end ),
    # LAW-008 tier
    ( if ($L.sku | lc) == "free" then
        $b + {control: "LAW-008", status: "FAIL", severity: "MEDIUM", actual: "Free tier (7-day retention, no data export)", evidence: $how}
      elif (($L.sku | lc) == "standalone" or ($L.sku | lc) == "pernode" or ($L.sku | lc) == "standard" or ($L.sku | lc) == "premium") then
        $b + {control: "LAW-008", status: "WARNING", severity: "LOW", actual: ("Legacy pricing tier " + $L.sku), evidence: $how}
      else $b + {control: "LAW-008", status: "PASS", actual: ("Pricing tier " + $L.sku), evidence: $how} end ),
    # LOGCAT-002 AzureDiagnostics usage
    ( if $L.azureDiagnosticsActive == true then
        $b + {control: "LOGCAT-002", status: "WARNING", severity: "LOW", expected: "Minimal AzureDiagnostics usage where resource-specific tables exist",
              actual: ("AzureDiagnostics ingested data in the last " + ($cfg.lookback | tostring) + " days"),
              evidence: (if ($L.azureDiagnosticsProviders | length) > 0 then "Last " + ($cfg.azdiagHours | tostring) + "h by provider/category: " + ($L.azureDiagnosticsProviders | map((.ResourceProvider // "?") + "/" + (.Category // "?") + "=" + (.Records | tostring)) | join(", ")) else "Usage table shows AzureDiagnostics volume" end),
              reason: "Governance/modernization finding - not a compliance failure.",
              recommendation: "Switch diagnostic settings to resource-specific mode where supported (see LOGCAT-001)."}
      elif $L.azureDiagnosticsActive == false then $b + {control: "LOGCAT-002", status: "PASS", actual: "No AzureDiagnostics ingestion observed"}
      else $b + {control: "LOGCAT-002", status: "NOT_VERIFIABLE", severity: "LOW", reason: ("Table activity unknown (" + $L.usageStatus + ")")} end ),
    # LOGCAT-003 inventory
    ( $b + {control: "LOGCAT-003", status: "NOT_APPLICABLE", reason: "Inventory",
            evidence: ("Active App* tables: " + ($L.activeAppTables | join(", ")) + " | CustomLogs (_CL): " + ($L.customLogTables | join(", ")) + " | AzureDiagnostics active: " + ($L.azureDiagnosticsActive | tostring))} );
JQEOF
}

# =============================================================================
# LOG ANALYTICS WORKSPACES
# API: GET {ws}?api-version=2022-10-01                    workspace properties
#      GET {ws}/tables?api-version=2022-10-01             table plan/retention (table-level)
#      GET {ws}/dataExports?api-version=2020-08-01        Data Export rules
#      POST {LA}/v1/workspaces/{customerId}/query         'Usage' metadata query (read-only)
# =============================================================================
audit_log_analytics() { # <sub> <subname>
  local sub="$1" subname="$2" line n
  n="$(by_type "$sub" '^microsoft\.operationalinsights/workspaces$' | wc -l | tr -d ' ')"
  log_info "Found $n Log Analytics Workspaces"
  while IFS= read -r line; do
    pool_run audit_law_workspace "$sub" "$subname" "$line"
  done < <(by_type "$sub" '^microsoft\.operationalinsights/workspaces$')
  pool_wait
}

audit_law_workspace() { # <sub> <subname> <resource json>
  local sub="$1" subname="$2" r="$3" id name ws tables usage azd exports bundle rec trec f
  local rc ts="OK" te="" us="OK" ue="" es="OK" ee="" ev cid apiv
  id="$(printf '%s' "$r" | jq -r .id)"; name="$(printf '%s' "$r" | jq -r .name)"
  ws="$(tmpf)"; tables="$(tmpf)"; usage="$(tmpf)"; azd="$(tmpf)"; exports="$(tmpf)"
  bundle="$(tmpf)"; rec="$(tmpf)"; trec="$(tmpf)"; f="$(tmpf)"
  arm_get "$id" "$ws" $API_LAW; rc=$?
  if [ $rc -ne 0 ]; then
    record_error law workspace-get "$id" "$(rc_name $rc)" "$(err_msg "$ws")" "$sub"
    emit law "$(jq -nc --arg id "$(lower "$id")" --arg n "$name" --arg s "$sub" --arg sn "$subname" --arg st "$(rc_name $rc)" --arg e "$(err_msg "$ws")" \
      '{id: $id, name: $n, subscriptionId: $s, subscriptionName: $sn, auditStatus: $st, auditError: $e}')"
    add_finding control=LAW-001 status="$(rc_status $rc)" severity=HIGH resourceId="$id" resourceName="$name" \
      resourceType=microsoft.operationalinsights/workspaces reason="$(rc_name $rc): $(err_msg "$ws")" \
      evidence="GET $id?api-version=${API_LAW%% *}"
    rm -f "$ws" "$ws.err" "$tables" "$usage" "$azd" "$exports" "$bundle" "$rec" "$trec" "$f"; return
  fi
  apiv="$(cat "$ws.apiversion" 2>/dev/null || echo "${API_LAW%% *}")"
  ev="$(save_raw law "$id" "$ws")"
  cid="$(jq -r '.properties.customerId // ""' "$ws")"

  echo '[]' > "$tables"
  if [ "$OPT_SKIP_TABLES" = true ]; then ts=SKIPPED
  else
    arm_list "$id/tables" "$tables" "$apiv"; rc=$?
    if [ $rc -ne 0 ]; then ts="$(rc_name $rc)"; te="$(err_msg "$tables")"; echo '[]' > "$tables"
      record_error law tables "$id" "$ts" "$te" "$sub"
    else save_raw law-tables "$id" "$tables" >/dev/null; fi
  fi

  echo 'null' > "$usage"; echo '[]' > "$azd"
  if [ "$ENABLE_DATA_QUERIES" != true ] || [ "$OPT_SKIP_TABLES" = true ]; then us=SKIPPED; ue="data queries disabled"
  elif [ -z "$cid" ]; then us=ERROR; ue="workspace customerId unknown"
  else
    la_query "$cid" "Usage | where TimeGenerated > ago(${ACTIVE_TABLE_LOOKBACK_DAYS}d) | summarize LastSeen = max(TimeGenerated), VolumeMB = round(sum(Quantity), 3) by DataType | order by DataType asc" \
      "P${ACTIVE_TABLE_LOOKBACK_DAYS}D" "$usage"; rc=$?
    if [ $rc -ne 0 ]; then us="$(rc_name $rc)"; ue="$(err_msg "$usage")"; echo 'null' > "$usage"
      record_error law usage-query "$id" "$us" "$ue" "$sub"
    else
      save_raw law-usage "$id" "$usage" >/dev/null
      if [ "$AZDIAG_QUERY" = true ] && jq -e 'map(.DataType) | index("AzureDiagnostics")' "$usage" >/dev/null 2>&1; then
        la_query "$cid" "AzureDiagnostics | where TimeGenerated > ago(${AZDIAG_LOOKBACK_HOURS}h) | summarize Records = count() by ResourceProvider, Category | top 200 by Records desc" \
          "PT${AZDIAG_LOOKBACK_HOURS}H" "$azd"; rc=$?
        if [ $rc -ne 0 ]; then record_error law azurediagnostics-query "$id" "$(rc_name $rc)" "$(err_msg "$azd")" "$sub"; echo '[]' > "$azd"; fi
      fi
    fi
  fi

  get_all_pages "$(arm_url "$id/dataExports" "$API_LAW_EXPORT")" "$exports"; rc=$?
  if [ $rc -ne 0 ]; then es="$(rc_name $rc)"; ee="$(err_msg "$exports")"; echo '[]' > "$exports"
    record_error law data-exports "$id" "$es" "$ee" "$sub"
  else save_raw law-data-exports "$id" "$exports" >/dev/null; fi

  jq -n --argjson res "$(printf '%s' "$r" | jq -c --arg sn "$subname" '. + {subscriptionName: $sn} | del(.properties)')" \
     --slurpfile ws "$ws" --slurpfile t "$tables" --slurpfile u "$usage" --slurpfile a "$azd" --slurpfile e "$exports" \
     --arg ts "$ts" --arg te "$te" --arg us "$us" --arg ue "$ue" --arg es "$es" --arg ee "$ee" --arg ev "$ev" \
     '{resource: $res, ws: $ws[0], tables: $t[0], usage: $u[0], azdiag: $a[0], exports: $e[0],
       tablesStatus: $ts, tablesError: $te, usageStatus: $us, usageError: $ue, exportsStatus: $es, exportsError: $ee, evidenceFile: $ev}' > "$bundle"
  jqlib 'law_tables_eval($cfg; $sup[0])' -c --argjson cfg "$LAW_CFG" --slurpfile sup "$WORK/supported_tables.json" "$bundle" > "$trec"
  jqlib 'law_record($cfg; $t[0])' -c --argjson cfg "$LAW_CFG" --slurpfile t "$trec" "$bundle" > "$rec"
  emit_file law "$rec"
  jq -c '.[]' "$trec" >> "$SHARD_DIR/law_tables.jsonl"
  jq -c '. as $l | .exportRules[] | {workspaceId: $l.id, workspaceName: $l.name, subscriptionId: $l.subscriptionId, rule: .name,
          enabled, destinationType, destinationId, eventHubName, tables, tableCount: (.tables | length), createdDate, lastModifiedDate}' "$rec" >> "$SHARD_DIR/law_exports.jsonl"
  jqlib 'law_findings($cfg; $t[0])' -c --argjson cfg "$LAW_CFG" --slurpfile t "$trec" "$rec" > "$f"
  ingest_findings "$f"
  rm -f "$ws" "$ws.apiversion" "$tables" "$tables.apiversion" "$usage" "$azd" "$exports" "$bundle" "$rec" "$trec" "$f" \
        "$tables.err" "$usage.err" "$azd.err" "$exports.err"
}

build_law_cfg() {
  local sup="$WORK/supported_tables.json"
  if [ -n "$EXPORT_SUPPORTED_TABLES_FILE" ]; then
    if [ -r "$EXPORT_SUPPORTED_TABLES_FILE" ]; then
      jq -R 'gsub("^\\s+|\\s+$"; "") | select(. != "" and (startswith("#") | not)) | ascii_downcase' "$EXPORT_SUPPORTED_TABLES_FILE" | jq -s 'unique' > "$sup"
      log_info "Loaded $(jq length "$sup") supported export table names from $EXPORT_SUPPORTED_TABLES_FILE"
    else
      log_warn "EXPORT_SUPPORTED_TABLES_FILE '$EXPORT_SUPPORTED_TABLES_FILE' not readable - export eligibility stays heuristic"
      echo 'null' > "$sup"
    fi
  else
    echo 'null' > "$sup"
  fi
  LAW_CFG="$(jq -nc --argjson hotMin "$HOT_RETENTION_MIN_DAYS" --argjson hotMax "$HOT_RETENTION_MAX_DAYS" \
     --argjson debugMax "$DEBUG_RETENTION_MAX_DAYS" --arg debugRegex "$DEBUG_TABLE_REGEX" --arg exemptRegex "$HOT_RETENTION_EXEMPT_TABLE_REGEX" \
     --arg securityTableRegex "$SECURITY_TABLE_REGEX" --arg exportUnsupportedRegex "$EXPORT_UNSUPPORTED_TABLE_REGEX" \
     --arg plans "$EXPORT_UNSUPPORTED_PLANS" --arg lawExcludeRegex "$LAW_EXCLUDE_REGEX" --arg apiLaw "${API_LAW%% *}" \
     --arg apiExport "$API_LAW_EXPORT" --argjson lookback "$ACTIVE_TABLE_LOOKBACK_DAYS" --argjson azdiagHours "$AZDIAG_LOOKBACK_HOURS" \
     '{hotMin: $hotMin, hotMax: $hotMax, debugMax: $debugMax, debugRegex: $debugRegex, exemptRegex: $exemptRegex,
       securityTableRegex: $securityTableRegex, exportUnsupportedRegex: $exportUnsupportedRegex,
       unsupportedPlans: ($plans | split(" ") | map(select(. != ""))), lawExcludeRegex: $lawExcludeRegex,
       apiLaw: $apiLaw, apiExport: $apiExport, lookback: $lookback, azdiagHours: $azdiagHours}')"
}

# =============================================================================
# EVENT HUBS
# API: GET {ns}, {ns}/networkRuleSets/default, {ns}/authorizationRules (names and
#      rights only - keys are never requested), {ns}/eventhubs, {hub}/consumergroups,
#      {hub}/authorizationRules, {ns}/providers/Microsoft.Insights/metrics
# =============================================================================
audit_event_hubs() { # <sub> <subname>
  local sub="$1" subname="$2" line n
  n="$(by_type "$sub" '^microsoft\.eventhub/namespaces$' | wc -l | tr -d ' ')"
  log_info "Found $n Event Hub namespaces"
  while IFS= read -r line; do
    pool_run audit_eventhub_namespace "$(printf '%s' "$line" | jq -r .id)" "$subname" false
  done < <(by_type "$sub" '^microsoft\.eventhub/namespaces$')
  pool_wait
}

metrics_window() { # prints start/end ISO timespan for the last N hours
  jq -rn --argjson h "$1" '((now - ($h * 3600)) | strftime("%Y-%m-%dT%H:%M:%SZ")) + "/" + (now | strftime("%Y-%m-%dT%H:%M:%SZ"))'
}

audit_eventhub_namespace() { # <namespace id> <subname> <external:true|false>
  local id="$1" subname="$2" external="$3" ns net rules hubs hubx met rec f rc apiv hid ns_s="OK" net_s="OK" met_s="OK" ev cg hr
  ns="$(tmpf)"; net="$(tmpf)"; rules="$(tmpf)"; hubs="$(tmpf)"; hubx="$(tmpf)"; met="$(tmpf)"; rec="$(tmpf)"; f="$(tmpf)"
  arm_get "$id" "$ns" $API_EH; rc=$?
  if [ $rc -ne 0 ]; then
    record_error eventhub namespace-get "$id" "$(rc_name $rc)" "$(err_msg "$ns")"
    emit eventhubs "$(jq -nc --arg id "$(lower "$id")" --arg st "$(rc_name $rc)" --arg e "$(err_msg "$ns")" --argjson ext "$external" \
       '{kind: "namespace", id: $id, name: ($id | split("/") | last), subscriptionId: ($id | split("/")[2]), auditStatus: $st, auditError: $e, outOfScope: $ext}')"
    rm -f "$ns" "$ns.err" "$net" "$rules" "$hubs" "$hubx" "$met" "$rec" "$f"; return
  fi
  apiv="$(cat "$ns.apiversion" 2>/dev/null || echo "${API_EH%% *}")"
  ev="$(save_raw eventhub "$id" "$ns")"
  arm_get "$id/networkRuleSets/default" "$net" "$apiv"; rc=$?
  if [ $rc -ne 0 ]; then net_s="$(rc_name $rc)"; echo 'null' > "$net"; record_error eventhub network-rule-set "$id" "$net_s" "$(err_msg "$net")"; fi
  arm_list "$id/authorizationRules" "$rules" "$apiv"; rc=$?
  if [ $rc -ne 0 ]; then echo '[]' > "$rules"; record_error eventhub authorization-rules "$id" "$(rc_name $rc)" "$(err_msg "$rules")"; fi
  arm_list "$id/eventhubs" "$hubs" "$apiv"; rc=$?
  if [ $rc -ne 0 ]; then ns_s="HUBS_$(rc_name $rc)"; echo '[]' > "$hubs"; record_error eventhub eventhubs-list "$id" "$(rc_name $rc)" "$(err_msg "$hubs")"; fi
  : > "$hubx"
  cg="$(tmpf)"; hr="$(tmpf)"
  while IFS= read -r hid; do
    [ -n "$hid" ] || continue
    arm_list "$hid/consumergroups" "$cg" "$apiv" || { record_error eventhub consumer-groups "$hid" "$(rc_name $?)" "$(err_msg "$cg")"; echo 'null' > "$cg"; }
    arm_list "$hid/authorizationRules" "$hr" "$apiv" || { echo '[]' > "$hr"; }
    jq -nc --arg id "$(lower "$hid")" --slurpfile c "$cg" --slurpfile r "$hr" \
      '{id: $id, consumerGroups: (if $c[0] == null then null else [$c[0][] | .name] end), rules: [$r[0][] | {name, rights: (.properties.rights // [])}]}' >> "$hubx"
  done < <(jq -r '.[].id' "$hubs")
  rm -f "$cg" "$cg.err" "$hr" "$hr.err"
  az_call get "$(arm_url "$id/providers/Microsoft.Insights/metrics" "$API_METRICS")&metricnames=IncomingMessages,OutgoingMessages&aggregation=Total&interval=PT1H&timespan=$(metrics_window "$EH_METRICS_LOOKBACK_HOURS")&%24filter=EntityName%20eq%20%27%2A%27" "$met"; rc=$?
  if [ $rc -ne 0 ]; then met_s="$(rc_name $rc)"; echo 'null' > "$met"; record_error eventhub metrics "$id" "$met_s" "$(err_msg "$met")"; fi

  jqlib '
    $ns[0] as $n | ($net[0] // {}) as $nr | ($hx | map({key: .id, value: .}) | from_entries) as $X
    | (if $met[0] == null then null else
        ([ $met[0].value[]? | (.name.value) as $m | .timeseries[]?
           | (((.metadatavalues // []) | map(select((.name.value | lc) == "entityname")) | .[0].value) // "") as $h
           | {metric: $m, hub: ($h | lc), total: ([.data[]? | .total // 0] | add // 0)} ]
         | group_by(.hub) | map({key: .[0].hub, value: (map({key: .metric, value: .total}) | from_entries)}) | from_entries) end) as $M
    | ($hubs[0] | map(
        (.properties // {}) as $p | (.id | lc) as $hid
        | { kind: "eventhub", id: $hid, name: .name, namespaceId: ($n.id | lc), namespaceName: $n.name,
            subscriptionId: ($n.id | sub_of), subscriptionName: $subname, resourceGroup: ($n.id | rg_of),
            partitionCount: ($p.partitionCount // null), status: ($p.status // null),
            retentionHours: (($p.retentionDescription.retentionTimeInHours // null) // (if $p.messageRetentionInDays != null then $p.messageRetentionInDays * 24 else null end)),
            messageRetentionInDays: ($p.messageRetentionInDays // null),
            captureEnabled: ($p.captureDescription.enabled // false),
            captureDestination: ($p.captureDescription.destination.name // null),
            captureStorageAccountId: (($p.captureDescription.destination.properties.storageAccountResourceId // null) | if . == null then null else lc end),
            captureContainer: ($p.captureDescription.destination.properties.blobContainer // null),
            consumerGroups: ($X[$hid].consumerGroups // null),
            criblConsumerGroups: [($X[$hid].consumerGroups // [])[] | select(rx($cfg.criblCgRegex))],
            authorizationRules: ($X[$hid].rules // []),
            incomingMessages: (if $M == null then null else ($M[(.name | lc)].IncomingMessages // 0) end),
            outgoingMessages: (if $M == null then null else ($M[(.name | lc)].OutgoingMessages // 0) end),
            isSecurityStream: ((.name | rx($cfg.ehRegex)) or ($n.name | rx($cfg.ehRegex))),
            outOfScope: $ext, auditStatus: "OK" })) as $H
    | ($n.properties // {}) as $np
    | { kind: "namespace", id: ($n.id | lc), name: $n.name, subscriptionId: ($n.id | sub_of), subscriptionName: $subname,
        resourceGroup: ($n.id | rg_of), location: ($n.location // ""),
        skuName: ($n.sku.name // ""), skuTier: ($n.sku.tier // ""), capacity: ($n.sku.capacity // null),
        autoInflate: ($np.isAutoInflateEnabled // false), maxThroughputUnits: ($np.maximumThroughputUnits // null),
        kafkaEnabled: ($np.kafkaEnabled // null), zoneRedundant: ($np.zoneRedundant // null),
        publicNetworkAccess: ($np.publicNetworkAccess // "Enabled"), minimumTlsVersion: ($np.minimumTlsVersion // "unknown"),
        disableLocalAuth: ($np.disableLocalAuth // false),
        networkRuleSetStatus: $netst, networkDefaultAction: ($nr.properties.defaultAction // null),
        trustedServiceAccessEnabled: ($nr.properties.trustedServiceAccessEnabled // false),
        ipRules: (($nr.properties.ipRules // []) | length), vnetRules: (($nr.properties.virtualNetworkRules // []) | length),
        privateEndpoints: [($np.privateEndpointConnections // [])[] | {name: (.name // (.id | name_of)), status: (.properties.privateLinkServiceConnectionState.status // "")}],
        approvedPrivateEndpoints: ([($np.privateEndpointConnections // [])[] | select((.properties.privateLinkServiceConnectionState.status // "") == "Approved")] | length),
        authorizationRules: [$rules[0][] | {name, rights: (.properties.rights // [])}],
        hubCount: ($H | length), hubs: [$H[].name],
        isSecurityStream: (($n.name | rx($cfg.ehRegex)) or ([$H[] | select(.isSecurityStream)] | length > 0)),
        metricsStatus: $metst,
        incomingMessages: (if $M == null then null else ([$M[] | .IncomingMessages // 0] | add // 0) end),
        outgoingMessages: (if $M == null then null else ([$M[] | .OutgoingMessages // 0] | add // 0) end),
        outOfScope: $ext, auditStatus: $nsst, auditError: "", evidenceFile: $ev }
    | ., $H[]' -c --slurpfile ns "$ns" --slurpfile net "$net" --slurpfile rules "$rules" --slurpfile hubs "$hubs" \
       --slurpfile met "$met" --arg subname "$subname" --argjson ext "$external" \
       --arg netst "$net_s" --arg metst "$met_s" --arg nsst "$ns_s" --arg ev "$ev" --argjson cfg "$EH_CFG" \
       --slurpfile hx "$hubx" -n > "$rec"
  emit_file eventhubs "$rec"

  jqlib '
    select(.kind == "namespace") | . as $n
    | {subscriptionId: $n.subscriptionId, resourceId: $n.id, resourceType: "microsoft.eventhub/namespaces", resourceName: $n.name, evidenceFile: $n.evidenceFile} as $b
    | (if $n.isSecurityStream then "MEDIUM" else "LOW" end) as $sev
    | ( if $n.networkRuleSetStatus != "OK" then
          $b + {control: "EH-003", status: "NOT_VERIFIABLE", severity: $sev, reason: ("networkRuleSets/default: " + $n.networkRuleSetStatus)}
        elif ($n.publicNetworkAccess != "Disabled") and (($n.networkDefaultAction // "Allow") == "Allow") then
          $b + {control: "EH-003", status: "WARNING", severity: $sev, expected: "Firewall (defaultAction Deny) or private endpoints only",
                actual: ("publicNetworkAccess=" + $n.publicNetworkAccess + ", defaultAction=" + ($n.networkDefaultAction // "Allow") + ", approved private endpoints=" + ($n.approvedPrivateEndpoints | tostring)),
                reason: "Namespace accepts connections from all networks.",
                recommendation: "Restrict network access; keep trusted Microsoft services enabled so LAW Data Export can deliver."}
        else
          $b + {control: "EH-003", status: "PASS", actual: ("publicNetworkAccess=" + $n.publicNetworkAccess + ", defaultAction=" + ($n.networkDefaultAction // "n/a") + ", trustedServices=" + ($n.trustedServiceAccessEnabled | tostring) + ", privateEndpoints=" + ($n.approvedPrivateEndpoints | tostring))}
        end ),
      ( ([ (if (($n.minimumTlsVersion // "") | test("^1\\.[23]$")) | not then "minimumTlsVersion=" + ($n.minimumTlsVersion // "unknown") else empty end),
           (if ($n.disableLocalAuth | not) then "local SAS authentication enabled" else empty end) ]) as $iss
        | if ($iss | length) > 0 then $b + {control: "EH-006", status: "WARNING", severity: (if $n.isSecurityStream then "MEDIUM" else "LOW" end), actual: ($iss | join(", ")),
                                            recommendation: "Set minimum TLS 1.2 and prefer Entra ID (disableLocalAuth=true) for consumers such as Cribl."}
          else $b + {control: "EH-006", status: "PASS", actual: ("TLS " + $n.minimumTlsVersion + ", local auth disabled")} end ),
      ( if $n.isSecurityStream then
          ([$hubs0[] | select(.kind == "eventhub" and .namespaceId == $n.id and ((.retentionHours // 0) < ($cfg.ehMinRetentionDays * 24)))]) as $low
          | if ($low | length) > 0 then
              $b + {control: "EH-007", status: "WARNING", severity: "LOW", expected: ("Hub retention >= " + ($cfg.ehMinRetentionDays | tostring) + " day(s) to buffer SOC outages"),
                    actual: ($low | map(.name + "=" + ((.retentionHours // 0) | tostring) + "h") | join(", ")),
                    evidence: ("sku=" + $n.skuName + ", capacity=" + ($n.capacity | tostring) + ", autoInflate=" + ($n.autoInflate | tostring))}
            else
              $b + {control: "EH-007", status: "PASS", actual: ("sku=" + $n.skuName + ", capacity=" + ($n.capacity | tostring) + ", autoInflate=" + ($n.autoInflate | tostring) + ", hubs=" + ($n.hubCount | tostring))}
            end
        else empty end )' -c --argjson cfg "$EH_CFG" --slurpfile hubs0 "$rec" "$rec" > "$f"
  ingest_findings "$f"
  rm -f "$ns" "$ns.apiversion" "$net" "$net.err" "$rules" "$rules.apiversion" "$hubs" "$hubs.apiversion" "$hubx" "$met" "$rec" "$f" \
        "$rules.err" "$hubs.err" "$met.err" "$net.apiversion"
}

build_eh_cfg() {
  EH_CFG="$(jq -nc --arg ehRegex "$EXPECTED_EVENTHUB_REGEX" --arg criblCgRegex "$CRIBL_CONSUMER_GROUP_REGEX" \
            --argjson ehMinRetentionDays "$EH_MIN_RETENTION_DAYS" \
            '{ehRegex: $ehRegex, criblCgRegex: $criblCgRegex, ehMinRetentionDays: $ehMinRetentionDays}')"
}

# =============================================================================
# APPLICATION INSIGHTS
# API: properties from Resource Graph; fallback GET {component}?api-version=2020-02-02
# =============================================================================
audit_application_insights() { # <sub> <subname>
  local sub="$1" subname="$2" line id t rc f n
  n="$(by_type "$sub" '^microsoft\.insights/components$' | wc -l | tr -d ' ')"
  [ "$n" -gt 0 ] && log_info "Auditing $n Application Insights components..."
  f="$(tmpf)"
  while IFS= read -r line; do
    id="$(printf '%s' "$line" | jq -r .id)"
    t="$(tmpf)"
    if [ "$(printf '%s' "$line" | jq -r '.properties == null')" = true ]; then
      arm_get "$id" "$t" "$API_APPI"; rc=$?
      if [ $rc -ne 0 ]; then
        record_error appinsights component-get "$id" "$(rc_name $rc)" "$(err_msg "$t")" "$sub"
        add_finding control=APP-001 status="$(rc_status $rc)" severity=MEDIUM resourceId="$id" resourceType=microsoft.insights/components \
          reason="$(rc_name $rc): $(err_msg "$t")"
        rm -f "$t" "$t.err" "$t.apiversion"; continue
      fi
      jqlib 'redact | .properties' "$t" > "$t.p"
    else
      printf '%s' "$line" | jqlib 'redact | .properties' > "$t.p"
    fi
    printf '%s' "$line" | jq -c --slurpfile p "$t.p" --arg sn "$subname" '
      ($p[0] // {}) as $q
      | {id: (.id | ascii_downcase), name, subscriptionId, subscriptionName: $sn, resourceGroup, location,
         applicationType: ($q.Application_Type // $q.applicationType // null),
         workspaceResourceId: (($q.WorkspaceResourceId // $q.workspaceResourceId // "") | ascii_downcase),
         ingestionMode: ($q.IngestionMode // $q.ingestionMode // null),
         retentionInDays: ($q.RetentionInDays // $q.retentionInDays // null),
         disableLocalAuth: ($q.DisableLocalAuth // $q.disableLocalAuth // false),
         publicNetworkAccessForIngestion: ($q.publicNetworkAccessForIngestion // null),
         publicNetworkAccessForQuery: ($q.publicNetworkAccessForQuery // null),
         workspaceBased: ((($q.WorkspaceResourceId // $q.workspaceResourceId // "") != "") and ((($q.IngestionMode // $q.ingestionMode // "LogAnalytics") | ascii_downcase) == "loganalytics"))}' \
      >> "$SHARD_DIR/appinsights.jsonl"
    printf '%s' "$line" | jq -c --slurpfile p "$t.p" '
      ($p[0] // {}) as $q | ($q.WorkspaceResourceId // $q.workspaceResourceId // "") as $w
      | {subscriptionId, resourceId: .id, resourceType: "microsoft.insights/components", resourceName: .name} as $b
      | ( if $w != "" and ((($q.IngestionMode // "LogAnalytics") | ascii_downcase) == "loganalytics") then
            $b + {control: "APP-001", status: "PASS", actual: ("Workspace-based -> " + ($w | split("/") | last))}
          else
            $b + {control: "APP-001", status: "FAIL", severity: "MEDIUM", expected: "Workspace-based Application Insights (IngestionMode=LogAnalytics)",
                  actual: ("Classic / non-workspace architecture (IngestionMode=" + (($q.IngestionMode // "unknown") | tostring) + ")"),
                  reason: "Classic Application Insights was retired; telemetry does not land in LAW and cannot reach the LAW -> Event Hub pipeline.",
                  recommendation: "Migrate the component to workspace-based mode targeting the central LAW."}
          end ),
        ( if (($q.DisableLocalAuth // false) | not) then
            $b + {control: "APP-003", status: "WARNING", severity: "LOW", actual: "Local (instrumentation key) authentication enabled",
                  reason: "Ingestion with only the connection string permits spoofed telemetry, weakening audit-event integrity.",
                  recommendation: "Enable Entra ID authenticated ingestion (DisableLocalAuth=true)."}
          else $b + {control: "APP-003", status: "PASS", actual: "Local authentication disabled"} end )' >> "$f"
    rm -f "$t" "$t.p" "$t.err" "$t.apiversion"
  done < <(by_type "$sub" '^microsoft\.insights/components$')
  ingest_findings "$f"; rm -f "$f"
}

# =============================================================================
# POSTGRESQL / MYSQL FLEXIBLE SERVER
# API: GET {server}/configurations (paged)   - pgaudit / logging parameters
#      GET {server}/configurations/{name}    - MySQL audit parameters
# Data-plane state (CREATE EXTENSION pgaudit per database) is not visible via ARM.
# =============================================================================
audit_postgresql() { # <sub> <subname>
  local sub="$1" subname="$2" line
  while IFS= read -r line; do
    pool_run audit_pg_server "$line" "$subname"
  done < <(by_type "$sub" '^microsoft\.dbforpostgresql/flexibleservers$')
  pool_wait
  local f; f="$(tmpf)"
  by_type "$sub" '^microsoft\.dbforpostgresql/servers$' | jq -c '{subscriptionId, resourceId: .id, resourceType: .type, resourceName: .name,
     control: "DB-004", status: "WARNING", severity: "HIGH", actual: "Azure Database for PostgreSQL Single Server (retired service)",
     recommendation: "Migrate to Flexible Server; audit logging capabilities of Single Server are no longer supported."}' > "$f"
  ingest_findings "$f"; rm -f "$f"
}

audit_pg_server() { # <resource json> <subname>
  local r="$1" subname="$2" id cfg rc st="OK" er="" rec f ev
  id="$(printf '%s' "$r" | jq -r .id)"
  cfg="$(tmpf)"; rec="$(tmpf)"; f="$(tmpf)"
  arm_list "$id/configurations" "$cfg" $API_PG; rc=$?
  if [ $rc -ne 0 ]; then st="$(rc_name $rc)"; er="$(err_msg "$cfg")"; echo '[]' > "$cfg"; record_error postgresql configurations "$id" "$st" "$er"
  else ev="$(save_raw postgresql-config "$id" "$cfg")"; fi
  printf '%s' "$r" | jq -c --slurpfile c "$cfg" --arg st "$st" --arg er "$er" --arg sn "$subname" --arg req "$PGAUDIT_REQUIRED_CLASSES" --arg ev "${ev:-}" '
    ($c[0] | map({key: (.name | ascii_downcase), value: (.properties.value // "")}) | from_entries) as $m
    | (($m["shared_preload_libraries"] // "") | ascii_downcase | split(",") | map(gsub("^\\s+|\\s+$"; ""))) as $spl
    | (($m["pgaudit.log"] // "") | ascii_downcase | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(. != ""))) as $cls
    | (["read", "write", "function", "role", "ddl", "misc", "misc_set"]) as $all
    | (if ($cls | index("all")) then $all else [] end + [$cls[] | select(startswith("-") | not)] | unique
       | . - [$cls[] | select(startswith("-")) | ltrimstr("-")]) as $eff
    | ($req | split(" ") | map(select(. != ""))) as $reqc
    | {engine: "PostgreSQLFlexible", id: (.id | ascii_downcase), name, subscriptionId, subscriptionName: $sn, resourceGroup, location,
       auditStatus: $st, auditError: $er,
       pgauditLoaded: (($spl | index("pgaudit")) != null),
       sharedPreloadLibraries: ($m["shared_preload_libraries"] // null),
       azureExtensions: ($m["azure.extensions"] // null),
       pgauditLog: ($m["pgaudit.log"] // null), pgauditEffectiveClasses: $eff,
       pgauditMissingClasses: ($reqc - $eff),
       pgauditLogParameter: ($m["pgaudit.log_parameter"] // null), pgauditLogRelation: ($m["pgaudit.log_relation"] // null),
       pgauditLogCatalog: ($m["pgaudit.log_catalog"] // null), pgauditRole: ($m["pgaudit.role"] // null),
       logConnections: ($m["log_connections"] // null), logDisconnections: ($m["log_disconnections"] // null),
       logStatement: ($m["log_statement"] // null), logLinePrefix: ($m["log_line_prefix"] // null),
       evidenceFile: $ev}' > "$rec"
  emit_file databases "$rec"
  jq -c --arg api "${API_PG%% *}" '
    . as $d | {subscriptionId: $d.subscriptionId, resourceId: $d.id, resourceType: "microsoft.dbforpostgresql/flexibleservers", resourceName: $d.name, evidenceFile: $d.evidenceFile} as $b
    | ("GET " + $d.id + "/configurations?api-version=" + $api) as $how
    | if $d.auditStatus != "OK" then
        $b + {control: "DB-001", status: (if $d.auditStatus == "FORBIDDEN" or $d.auditStatus == "AUTH" then "NOT_VERIFIABLE" else "ERROR" end), severity: "HIGH",
              reason: ("Server parameters not readable: " + $d.auditStatus + " " + $d.auditError), evidence: $how}
      else
        ( if $d.pgauditLoaded and (($d.pgauditEffectiveClasses | length) > 0) then
            $b + {control: "DB-001", status: "PASS", actual: ("pgaudit loaded; pgaudit.log=" + ($d.pgauditLog // "")),
                  evidence: ($how + " | note: per-database CREATE EXTENSION pgaudit is data-plane state, not visible via ARM")}
          else
            $b + {control: "DB-001", status: "FAIL", severity: "HIGH", expected: "pgaudit in shared_preload_libraries and pgaudit.log != none",
                  actual: ("shared_preload_libraries=" + ($d.sharedPreloadLibraries // "") + ", pgaudit.log=" + ($d.pgauditLog // "(unset)") + ", log_statement=" + ($d.logStatement // "")),
                  evidence: $how, reason: "Database data-plane auditing (pgaudit) is not active; Activity Logs do not cover data-plane operations.",
                  recommendation: "Add pgaudit to shared_preload_libraries (restart), allow-list it in azure.extensions, set pgaudit.log (e.g. ddl,write,role) and run CREATE EXTENSION pgaudit."}
          end ),
        ( ([ (if $d.pgauditLoaded and (($d.pgauditMissingClasses | length) > 0) then "pgaudit.log missing classes: " + ($d.pgauditMissingClasses | join(",")) else empty end),
             (if (($d.logConnections // "") | ascii_downcase) != "on" then "log_connections=" + ($d.logConnections // "unset") else empty end),
             (if (($d.logDisconnections // "") | ascii_downcase) != "on" then "log_disconnections=" + ($d.logDisconnections // "unset") else empty end),
             (if (($d.pgauditLogParameter // "") | ascii_downcase) == "on" then "pgaudit.log_parameter=on (statement parameter values - potential payload/PII - are logged)" else empty end) ]) as $iss
          | if ($iss | length) > 0 then $b + {control: "DB-004", status: "WARNING", severity: "MEDIUM", actual: ($iss | join("; ")), evidence: $how,
                                              recommendation: "Log connections/disconnections and the required pgaudit classes; keep parameter logging off (metadata-focused audit)."}
            else $b + {control: "DB-004", status: "PASS", actual: ("pgaudit classes " + ($d.pgauditEffectiveClasses | join(",")) + ", connections/disconnections logged"), evidence: $how} end )
      end' "$rec" > "$f"
  ingest_findings "$f"
  rm -f "$cfg" "$cfg.err" "$cfg.apiversion" "$rec" "$f"
}

audit_mysql() { # <sub> <subname>
  local sub="$1" subname="$2" line id a e rc1 rc2 rec f
  while IFS= read -r line; do
    id="$(printf '%s' "$line" | jq -r .id)"
    a="$(tmpf)"; e="$(tmpf)"; rec="$(tmpf)"; f="$(tmpf)"
    arm_get "$id/configurations/audit_log_enabled" "$a" $API_MYSQL; rc1=$?
    arm_get "$id/configurations/audit_log_events" "$e" $API_MYSQL; rc2=$?
    [ $rc1 -eq 0 ] || { record_error mysql audit_log_enabled "$id" "$(rc_name $rc1)" "$(err_msg "$a")" "$sub"; echo 'null' > "$a"; }
    [ $rc2 -eq 0 ] || echo 'null' > "$e"
    printf '%s' "$line" | jq -c --slurpfile a "$a" --slurpfile e "$e" --arg st "$(rc_name $rc1)" --arg er "$(err_msg "$a")" --arg sn "$subname" \
      '{engine: "MySQLFlexible", id: (.id | ascii_downcase), name, subscriptionId, subscriptionName: $sn, resourceGroup, location, auditStatus: $st,
        auditError: (if $st == "OK" then "" else $er end),
        auditLogEnabled: ($a[0].properties.value // null), auditLogEvents: ($e[0].properties.value // null)}' > "$rec"
    emit_file databases "$rec"
    jq -c '. as $d | {subscriptionId, resourceId: .id, resourceType: "microsoft.dbformysql/flexibleservers", resourceName: .name} as $b
      | if $d.auditStatus != "OK" then $b + {control: "DB-001", status: (if $d.auditStatus == "FORBIDDEN" then "NOT_VERIFIABLE" else "ERROR" end), severity: "HIGH", reason: ($d.auditStatus + " " + $d.auditError)}
        elif (($d.auditLogEnabled // "") | ascii_downcase) == "on" then
          ($b + {control: "DB-001", status: "PASS", actual: ("audit_log_enabled=ON, audit_log_events=" + ($d.auditLogEvents // ""))}),
          (if (($d.auditLogEvents // "") | test("DDL|DML|ADMIN"; "i")) then empty
           else $b + {control: "DB-004", status: "WARNING", severity: "MEDIUM", actual: ("audit_log_events=" + ($d.auditLogEvents // "")), recommendation: "Include CONNECTION, ADMIN, DDL and DML(_NONSELECT) events."} end)
        else $b + {control: "DB-001", status: "FAIL", severity: "HIGH", expected: "audit_log_enabled=ON", actual: ("audit_log_enabled=" + ($d.auditLogEnabled // "unknown")),
                   recommendation: "Enable audit_log_enabled and route MySqlAuditLogs to the central LAW."} end' "$rec" > "$f"
    ingest_findings "$f"
    rm -f "$a" "$e" "$a.err" "$e.err" "$a.apiversion" "$e.apiversion" "$rec" "$f"
  done < <(by_type "$sub" '^microsoft\.dbformysql/flexibleservers$')
}

# =============================================================================
# AZURE SQL
# API: GET {server}/auditingSettings/default           server auditing (data plane audit)
#      GET {server}/devOpsAuditingSettings/default     Microsoft support operations audit
#      GET {server}/databases/master/providers/Microsoft.Insights/diagnosticSettings(+Categories)
#      GET {db}/auditingSettings/default                database-level auditing
# (Activity Logs are control-plane only and are NOT treated as database auditing.)
# =============================================================================
audit_sql() { # <sub> <subname>
  local sub="$1" subname="$2" line f
  while IFS= read -r line; do
    pool_run audit_sql_server "$line" "$sub" "$subname"
  done < <(by_type "$sub" '^microsoft\.sql/servers$')
  pool_wait
  f="$(tmpf)"
  by_type "$sub" '^microsoft\.sql/managedinstances$' | jq -c --arg sn "$subname" '
     {engine: "SQLManagedInstance", id: (.id | ascii_downcase), name, subscriptionId, subscriptionName: $sn, resourceGroup, location,
      auditStatus: "NOT_VERIFIABLE", auditError: "Managed Instance auditing is configured with T-SQL (CREATE SERVER AUDIT); not exposed via ARM"}' >> "$SHARD_DIR/databases.jsonl"
  by_type "$sub" '^microsoft\.sql/managedinstances$' | jq -c '{subscriptionId, resourceId: .id, resourceType: .type, resourceName: .name,
     control: "DB-001", status: "NOT_VERIFIABLE", severity: "HIGH",
     reason: "SQL Managed Instance server audit objects are data-plane (T-SQL) configuration; see DB-002 for SQLSecurityAuditEvents diagnostic evidence."}' > "$f"
  ingest_findings "$f"; rm -f "$f"
}

audit_sql_server() { # <resource json> <sub> <subname>
  local r="$1" sub="$2" subname="$3" id aud dev md mc dba rc st="OK" er="" dst="OK" mst="OK" rec f dbid ev
  id="$(printf '%s' "$r" | jq -r .id)"
  aud="$(tmpf)"; dev="$(tmpf)"; md="$(tmpf)"; mc="$(tmpf)"; dba="$(tmpf)"; rec="$(tmpf)"; f="$(tmpf)"
  arm_get "$id/auditingSettings/default" "$aud" $API_SQL; rc=$?
  if [ $rc -ne 0 ]; then st="$(rc_name $rc)"; er="$(err_msg "$aud")"; echo 'null' > "$aud"; record_error sql auditingSettings "$id" "$st" "$er" "$sub"
  else ev="$(save_raw sql-auditing "$id" "$aud")"; fi
  arm_get "$id/devOpsAuditingSettings/default" "$dev" $API_SQL; rc=$?
  if [ $rc -ne 0 ]; then dst="$(rc_name $rc)"; echo 'null' > "$dev"; fi
  get_all_pages "$(arm_url "$id/databases/master/providers/Microsoft.Insights/diagnosticSettings" "$API_DIAG")" "$md"; rc=$?
  if [ $rc -ne 0 ]; then mst="$(rc_name $rc)"; echo '[]' > "$md"; record_error sql master-diagnostic-settings "$id" "$mst" "$(err_msg "$md")" "$sub"; fi
  get_all_pages "$(arm_url "$id/databases/master/providers/Microsoft.Insights/diagnosticSettingsCategories" "$API_DIAG")" "$mc" || echo '[]' > "$mc"
  : > "$dba"
  local aud_state; aud_state="$(jq -r '.properties.state // "unknown"' "$aud")"
  if [ "$SQL_CHECK_DATABASE_AUDIT" = always ] || { [ "$SQL_CHECK_DATABASE_AUDIT" = auto ] && [ "$aud_state" != Enabled ]; }; then
    while IFS= read -r dbid; do
      [ -n "$dbid" ] || continue
      local t; t="$(tmpf)"
      arm_get "$dbid/auditingSettings/default" "$t" $API_SQL; rc=$?
      if [ $rc -eq 0 ]; then
        jq -c --arg id "$(lower "$dbid")" '{id: $id, state: (.properties.state // "unknown"), isAzureMonitorTargetEnabled: (.properties.isAzureMonitorTargetEnabled // false)}' "$t" >> "$dba"
      else
        jq -nc --arg id "$(lower "$dbid")" --arg st "$(rc_name $rc)" '{id: $id, state: $st, isAzureMonitorTargetEnabled: null}' >> "$dba"
      fi
      rm -f "$t" "$t.err" "$t.apiversion"
    done < <(jq -r --arg sid "$(lower "$id")" '.[] | select(.type == "microsoft.sql/servers/databases" and ((.id | ascii_downcase) | startswith($sid + "/databases/")) and ((.name | ascii_downcase) | endswith("/master") | not) and ((.name | ascii_downcase) != "master")) | .id' "$WORK/subs/$sub/resources.json")
  fi
  jqlib '
    ($aud[0].properties // null) as $a | ($dev[0].properties // null) as $d
    | ([$mc[0][] | select(((.properties.categoryType // "") | lc) == "logs") | .name]) as $logNames
    | ([$mc[0][] | select(((.properties.categoryType // "") | lc) == "logs") | {key: (.name | lc), value: ((.properties.categoryGroups // []) | map(lc))}] | from_entries) as $groupsOf
    | (if ($logNames | length) == 0 then ["SQLSecurityAuditEvents", "DevOpsOperationsAudit"] else $logNames end) as $ln
    | ($md[0] | settings_eval($ln; $groupsOf)) as $S
    | ((($a.storageEndpoint // "") | capture("^https://(?<n>[^.]+)\\.") | .n) // "") as $sa
    | {engine: "AzureSQL", id: ($res.id | lc), name: $res.name, subscriptionId: ($res.subscriptionId | lc), subscriptionName: $subname,
       resourceGroup: $res.resourceGroup, location: $res.location, auditStatus: $st, auditError: $er,
       auditState: ($a.state // null), isAzureMonitorTargetEnabled: ($a.isAzureMonitorTargetEnabled // false),
       storageEndpoint: ($a.storageEndpoint // ""), storageAccountName: ($sa // ""), retentionDays: ($a.retentionDays // null),
       auditActionsAndGroups: ($a.auditActionsAndGroups // []), isManagedIdentityInUse: ($a.isManagedIdentityInUse // null),
       isDevopsAuditEnabled: ($a.isDevopsAuditEnabled // null), devOpsAuditState: ($d.state // null), devOpsStatus: $dst,
       masterDiagStatus: $mst, masterSettingsSummary: ($S | settings_summary),
       auditToLaw: ([$S[] | select(.workspaceId != null and (.enabledCategories | index("SQLSecurityAuditEvents")))] | length > 0),
       auditToEventHub: ([$S[] | select(.eventHubAuthorizationRuleId != null and (.enabledCategories | index("SQLSecurityAuditEvents")))] | length > 0),
       auditToStorageViaDiag: ([$S[] | select(.storageAccountId != null and (.enabledCategories | index("SQLSecurityAuditEvents")))] | length > 0),
       masterWorkspaces: ([$S[] | select(.enabledCategories | index("SQLSecurityAuditEvents")) | .workspaceId | select(. != null) | lc] | unique),
       masterStorageAccounts: ([$S[] | select(.enabledCategories | index("SQLSecurityAuditEvents")) | .storageAccountId | select(. != null) | lc] | unique),
       devOpsToLaw: ([$S[] | select(.workspaceId != null and (.enabledCategories | index("DevOpsOperationsAudit")))] | length > 0),
       databaseAudits: $dbs, evidenceFile: $ev}' -c -n --argjson res "$(printf '%s' "$r" | jq -c 'del(.properties)')" --slurpfile aud "$aud" --slurpfile dev "$dev" \
         --slurpfile md "$md" --slurpfile mc "$mc" --argjson dbs "$(jq -sc '.' "$dba")" --arg st "$st" --arg er "$er" \
         --arg dst "$dst" --arg mst "$mst" --arg subname "$subname" --arg ev "${ev:-}" > "$rec"
  emit_file databases "$rec"
  jq -c --argjson amin "$ARCHIVE_RETENTION_MIN_DAYS" --arg api "$API_SQL" '
    . as $d | {subscriptionId: $d.subscriptionId, resourceId: $d.id, resourceType: "microsoft.sql/servers", resourceName: $d.name, evidenceFile: $d.evidenceFile} as $b
    | ("GET " + $d.id + "/auditingSettings/default?api-version=" + $api) as $how
    | if $d.auditStatus != "OK" then
        $b + {control: "DB-001", status: (if $d.auditStatus == "FORBIDDEN" or $d.auditStatus == "AUTH" then "NOT_VERIFIABLE" else "ERROR" end), severity: "HIGH",
              reason: ("auditingSettings not readable: " + $d.auditStatus + " " + $d.auditError), evidence: $how}
      else
        ([$d.databaseAudits[] | select(.state != "Enabled")]) as $dbOff
        | ( if $d.auditState == "Enabled" then $b + {control: "DB-001", status: "PASS", actual: "Server-level auditing Enabled (applies to all databases)", evidence: $how}
            elif ($d.databaseAudits | length) > 0 and ($dbOff | length) == 0 then
              $b + {control: "DB-001", status: "WARNING", severity: "MEDIUM", actual: "Server auditing disabled; every database has database-level auditing enabled",
                    evidence: $how, recommendation: "Prefer server-level auditing so new databases are covered automatically."}
            else
              $b + {control: "DB-001", status: "FAIL", severity: "HIGH", expected: "Server auditing Enabled (or database auditing on every database)",
                    actual: ("Server auditing " + ($d.auditState // "unknown") + (if ($dbOff | length) > 0 then "; databases without auditing: " + ($dbOff | map(.id | split("/") | last) | join(", ")) else "" end)),
                    evidence: $how, reason: "Database data-plane operations are not audited.",
                    recommendation: "Enable server auditing with Log Analytics (and immutable Storage) as destinations."}
            end ),
          ( if $d.auditState != "Enabled" then empty
            elif $d.isAzureMonitorTargetEnabled and $d.auditToLaw then
              $b + {control: "DB-002", status: "PASS", actual: ("SQLSecurityAuditEvents -> LAW " + ($d.masterWorkspaces | map(split("/") | last) | join(", "))), evidence: ("master diagnostic settings: " + $d.masterSettingsSummary)}
            elif $d.masterDiagStatus != "OK" then
              $b + {control: "DB-002", status: "NOT_VERIFIABLE", severity: "HIGH", reason: ("master database diagnostic settings: " + $d.masterDiagStatus)}
            else
              $b + {control: "DB-002", status: "FAIL", severity: "HIGH", expected: "Audit target Azure Monitor enabled and master diagnostic setting sends SQLSecurityAuditEvents to LAW",
                    actual: ("isAzureMonitorTargetEnabled=" + ($d.isAzureMonitorTargetEnabled | tostring) + ", storage=" + (if $d.storageEndpoint != "" then $d.storageAccountName else "none" end) + ", master settings: " + (if $d.masterSettingsSummary == "" then "none" else $d.masterSettingsSummary end)),
                    evidence: $how, reason: "SQL audit records are not centrally collected in LAW.",
                    recommendation: "Enable the Log Analytics audit destination (creates a master database diagnostic setting for SQLSecurityAuditEvents)."}
            end ),
          ( if $d.auditState != "Enabled" then empty
            elif $d.storageEndpoint == "" and ($d.masterStorageAccounts | length) == 0 then
              $b + {control: "DB-003", status: "WARNING", severity: "MEDIUM", actual: "No Storage audit destination (no direct long-term archive)",
                    recommendation: "Add the immutable archive Storage account as audit destination or archive via LAW Data Export."}
            elif $d.storageEndpoint != "" and ($d.retentionDays // 0) > 0 and ($d.retentionDays < $amin) then
              $b + {control: "DB-003", status: "FAIL", severity: "MEDIUM", expected: (">= " + ($amin | tostring) + " days (0 = unlimited)"),
                    actual: ("Storage audit retentionDays=" + ($d.retentionDays | tostring) + " on " + $d.storageAccountName), evidence: $how,
                    recommendation: "Set retentionDays to 0 (unlimited) and rely on locked immutability for deletion protection."}
            else
              $b + {control: "DB-003", status: "PASS", actual: ("Storage audit destination " + $d.storageAccountName + ", retentionDays=" + (($d.retentionDays // 0) | tostring) + " (WORM status: see ARC findings)"), evidence: $how}
            end ),
          ( if $d.auditState != "Enabled" then empty
            else ($d.auditActionsAndGroups) as $g
              | ((($g | index("SUCCESSFUL_AND_FAILED_DATABASE_AUTHENTICATION_GROUP")) != null) or ((($g | index("SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP")) != null) and (($g | index("FAILED_DATABASE_AUTHENTICATION_GROUP")) != null))) as $auth
              | ((($g | index("BATCH_COMPLETED_GROUP")) != null) or (($g | index("DATABASE_OBJECT_CHANGE_GROUP")) != null) or (($g | index("SCHEMA_OBJECT_CHANGE_GROUP")) != null)) as $chg
              | if $auth and $chg then $b + {control: "DB-004", status: "PASS", actual: ("auditActionsAndGroups: " + ($g | join(", "))), evidence: $how}
                else $b + {control: "DB-004", status: "WARNING", severity: "MEDIUM", expected: "Authentication (success+failure) and change/batch action groups audited",
                           actual: ("auditActionsAndGroups: " + ($g | join(", "))), evidence: $how} end
            end ),
          ( if $d.devOpsStatus != "OK" then $b + {control: "DB-005", status: "NOT_VERIFIABLE", severity: "LOW", reason: ("devOpsAuditingSettings: " + $d.devOpsStatus)}
            elif $d.devOpsAuditState == "Enabled" then $b + {control: "DB-005", status: "PASS", actual: ("DevOps auditing Enabled; to LAW=" + ($d.devOpsToLaw | tostring))}
            else $b + {control: "DB-005", status: "WARNING", severity: "LOW", actual: ("Microsoft support operations auditing " + ($d.devOpsAuditState // "unknown")),
                       recommendation: "Enable auditing of Microsoft support operations."} end )
      end' "$rec" > "$f"
  ingest_findings "$f"
  rm -f "$aud" "$dev" "$md" "$mc" "$dba" "$rec" "$f" "$aud.err" "$dev.err" "$md.err" "$mc.err" "$aud.apiversion" "$dev.apiversion"
}

# =============================================================================
# DATABRICKS
# Diagnostic categories are discovered through the generic diagnostic audit;
# here: tier and data-plane limitations. (Unity Catalog system tables, verbose
# audit logs, lineage require Databricks account/workspace APIs, not ARM.)
# =============================================================================
audit_databricks() { # <sub> <subname>
  local sub="$1" subname="$2" f
  f="$(tmpf)"
  by_type "$sub" '^microsoft\.databricks/workspaces$' | jq -c --arg sn "$subname" '
    {id: (.id | ascii_downcase), name, subscriptionId, subscriptionName: $sn, resourceGroup, location, sku: (.skuName // ""),
     workspaceUrl: (.properties.workspaceUrl // null), managedResourceGroupId: (.properties.managedResourceGroupId // null),
     publicNetworkAccess: (.properties.publicNetworkAccess // null),
     enableNoPublicIp: (.properties.parameters.enableNoPublicIp.value // null),
     requiredNsgRules: (.properties.requiredNsgRules // null)}' >> "$SHARD_DIR/databricks.jsonl"
  by_type "$sub" '^microsoft\.databricks/workspaces$' | jq -c '
    {subscriptionId, resourceId: .id, resourceType: .type, resourceName: .name} as $b
    | ((.skuName // "") | ascii_downcase) as $sku
    | ( if $sku == "premium" then $b + {control: "DBX-001", status: "PASS", actual: "Premium tier (diagnostic/audit logs available)"}
        elif $sku == "" then $b + {control: "DBX-001", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: "SKU not returned by inventory"}
        else $b + {control: "DBX-001", status: "FAIL", severity: "HIGH", expected: "Premium tier", actual: ("Tier " + $sku),
                   reason: "Azure Databricks diagnostic (audit) logs require the Premium tier.", recommendation: "Upgrade the workspace to Premium."} end ),
      ($b + {control: "DBX-004", status: "NOT_VERIFIABLE", severity: "MEDIUM",
             reason: "Verbose audit logs (workspace-conf enableVerboseAuditLogs), notebook command logging and data-access audit detail are Databricks workspace settings exposed only via the Databricks REST API, not Azure Resource Manager."}),
      ($b + {control: "DBX-005", status: "NOT_VERIFIABLE", severity: "LOW",
             reason: "Unity Catalog system tables (system.access.audit, system.access.table_lineage/column_lineage) require the Databricks account/SQL APIs; not inspectable from Azure."})' > "$f"
  ingest_findings "$f"; rm -f "$f"
}

# =============================================================================
# ENTRA ID (tenant level)
# API: GET /providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01
#      GET /providers/microsoft.aadiam/diagnosticSettingsCategories?api-version=2017-04-01-preview
# Azure CLI has no command for Entra diagnostic settings, hence az rest. Reading
# them requires an Entra role such as Security Reader/Global Reader plus ARM
# access at tenant scope; 403 is reported as NOT_VERIFIABLE (never FAIL).
# =============================================================================
audit_entra() {
  local s c rc rcc st="OK" er="" cst="OK" ev
  if [ "$OPT_SKIP_ENTRA" = true ]; then
    emit entra '{"auditStatus":"SKIPPED","auditError":"--skip-entra"}'; return
  fi
  log_info "Auditing Entra ID diagnostic settings (tenant level)..."
  s="$(tmpf)"; c="$(tmpf)"
  get_all_pages "$(arm_url "/providers/microsoft.aadiam/diagnosticSettings" "$API_AADIAM")" "$s"; rc=$?
  if [ $rc -ne 0 ]; then st="$(rc_name $rc)"; er="$(err_msg "$s")"; echo '[]' > "$s"
    record_error entra diagnosticSettings "/providers/microsoft.aadiam" "$st" "$er"
    log_warn "Entra diagnostic settings not readable ($st) - Entra controls fall back to LAW ingestion evidence"
  else ev="$(save_raw entra "/providers/microsoft.aadiam/diagnosticSettings" "$s")"; fi
  get_all_pages "$(arm_url "/providers/microsoft.aadiam/diagnosticSettingsCategories" "$API_AADIAM_CAT")" "$c"; rcc=$?
  if [ $rcc -ne 0 ]; then cst="$(rc_name $rcc)"; echo 'null' > "$c"; fi
  jqlib '
    ($c[0]) as $cats
    | (if $cats == null then null else [$cats[] | select(((.properties.categoryType // "Logs") | lc) == "logs") | .name] end) as $avail
    | (($avail // ["AuditLogs","SignInLogs","NonInteractiveUserSignInLogs","ServicePrincipalSignInLogs","ManagedIdentitySignInLogs","ProvisioningLogs","ADFSSignInLogs","RiskyUsers","UserRiskEvents","RiskyServicePrincipals","ServicePrincipalRiskEvents","MicrosoftGraphActivityLogs","NetworkAccessTrafficLogs","EnrichedOffice365AuditLogs"])) as $names
    | ($names | map({key: lc, value: []}) | from_entries) as $g
    | ($s[0] | settings_eval($names; $g)) as $S
    | {auditStatus: $st, auditError: $er, categoriesStatus: $cst, availableCategories: $avail,
       settingsCount: ($S | length), settings: $S, settingsSummary: ($S | settings_summary),
       categoriesToLaw: ([$S[] | select(.workspaceId != null) | .enabledCategories[]] | unique),
       categoriesToStorage: ([$S[] | select(.storageAccountId != null) | .enabledCategories[]] | unique),
       categoriesToEventHub: ([$S[] | select(.eventHubAuthorizationRuleId != null) | .enabledCategories[]] | unique),
       workspaces: ([$S[].workspaceId | select(. != null) | lc] | unique),
       storageAccounts: ([$S[].storageAccountId | select(. != null) | lc] | unique),
       eventHubNamespaces: ([$S[].eventHubNamespaceId | select(. != null) | lc] | unique),
       evidenceFile: $ev}' -c -n --slurpfile s "$s" --slurpfile c "$c" --arg st "$st" --arg er "$er" --arg cst "$cst" --arg ev "${ev:-}" \
     >> "$SHARD_DIR/entra.jsonl"
  rm -f "$s" "$c" "$s.err" "$c.err"
}

# =============================================================================
# STORAGE / WORM
# API: GET {sa}, {sa}/blobServices/default, {sa}/managementPolicies/default,
#      {sa}/blobServices/default/containers (paged),
#      {container}/immutabilityPolicies/default (when not embedded in the list)
# Only ARM management-plane reads; account keys / SAS are never requested.
# Blob-version-level WORM policies on individual blobs are data-plane state and
# are reported as NOT_VERIFIABLE when relevant.
# =============================================================================
collect_storage_targets() {
  local diag act entra law eh db inv
  diag="$(merged diagnostic)"; act="$(merged activity)"; entra="$(merged entra)"; law="$(merged law)"
  eh="$(merged eventhubs)"; db="$(merged databases)"; inv="$(merged resources)"
  jqlib '
    def refs($src; $kind): [$src[] | .[] | {id: ., kind: $kind}];
    ([ ($d | map(select(.auditStatus == "OK")) | map(.storageAccounts[]? | {id: ., kind: "diagnosticSetting"})),
       ($a | map(.storageAccounts[]? | {id: ., kind: "activityLog"})),
       ($e | map(.storageAccounts[]? | {id: ., kind: "entra"})),
       ($l | map(.storageDestinations[]? | {id: .storageAccountId, kind: "lawDataExport"})),
       ($h | map(select(.kind == "eventhub") | .captureStorageAccountId | select(. != null) | {id: ., kind: "eventHubCapture"})),
       ($db | map(.masterStorageAccounts[]? | {id: ., kind: "sqlAuditDiagnostic"})),
       ($db | map(select((.storageAccountName // "") != "") | .storageAccountName as $n
                  | ([$inv[] | select(.type == "microsoft.storage/storageaccounts" and ((.name | lc) == ($n | lc))) | .id | lc] | first) as $id
                  | if $id != null then {id: $id, kind: "sqlAudit"} else empty end)),
       ($inv | map(select(.type == "microsoft.storage/storageaccounts" and (.name | rx($re))) | {id: (.id | lc), kind: "nameMatch"}))
     ] | add // []) as $all
    | $all | map(select(.id != null and .id != "")) | group_by(.id | lc)
    | map({id: (.[0].id | lc), reasons: (map(.kind) | unique), referenced: (map(.kind) | map(select(. != "nameMatch")) | length > 0),
           referenceCount: (map(select(.kind != "nameMatch")) | length)})
    | .[]' -c -n --slurpfile d "$diag" --slurpfile a "$act" --slurpfile e "$entra" --slurpfile l "$law" \
       --slurpfile h "$eh" --slurpfile db "$db" --slurpfile inv "$inv" --arg re "$ARCHIVE_STORAGE_REGEX" \
       > "$WORK/storage_targets.jsonl" 2>"$WORK/storage_targets.err"
  if [ -s "$WORK/storage_targets.err" ]; then log_error "internal: storage target collection: $(head -c 300 "$WORK/storage_targets.err")"; fi
}

audit_storage() {
  collect_storage_targets
  local n line
  n="$(wc -l < "$WORK/storage_targets.jsonl" | tr -d ' ')"
  log_info "Auditing $n archive/logging storage account(s) (referenced by log destinations or matching ARCHIVE_STORAGE_REGEX)..."
  while IFS= read -r line; do
    pool_run audit_storage_account "$line"
  done < "$WORK/storage_targets.jsonl"
  pool_wait
}

audit_worm() { # WORM evaluation is performed per container inside audit_storage_account.
  audit_storage
}

audit_storage_account() { # <target json {id, reasons, referenced}>
  local tgt="$1" id acct blob mp cont rc apiv st="OK" bst="OK" mst="OK" cst="OK" rec wrec f ev cid pol line subname
  id="$(printf '%s' "$tgt" | jq -r .id)"
  subname="$(jq -r --arg s "$(printf '%s' "$id" | cut -d/ -f3)" '.[$s] // ""' "$WORK/subnames.json")"
  acct="$(tmpf)"; blob="$(tmpf)"; mp="$(tmpf)"; cont="$(tmpf)"; rec="$(tmpf)"; wrec="$(tmpf)"; f="$(tmpf)"
  arm_get "$id" "$acct" $API_STORAGE; rc=$?
  if [ $rc -ne 0 ]; then
    st="$(rc_name $rc)"
    record_error storage account-get "$id" "$st" "$(err_msg "$acct")"
    printf '%s' "$tgt" | jq -c --arg st "$st" --arg e "$(err_msg "$acct")" --arg sn "$subname" \
      '. + {name: (.id | split("/") | last), subscriptionId: (.id | split("/")[2]), subscriptionName: $sn, auditStatus: $st, auditError: $e}' >> "$SHARD_DIR/storage.jsonl"
    printf '%s' "$tgt" | jq -c --arg st "$st" --arg e "$(err_msg "$acct")" \
      '{control: "ARC-004", status: (if $st == "FORBIDDEN" or $st == "AUTH" or $st == "NOTFOUND" then "NOT_VERIFIABLE" else "ERROR" end),
        severity: (if .referenced then "HIGH" else "LOW" end), resourceId: .id, resourceType: "microsoft.storage/storageaccounts",
        reason: ("Storage account not readable (" + $st + "): " + $e + ". Referenced by: " + (.reasons | join(", ")))}' > "$f"
    ingest_findings "$f"
    rm -f "$acct" "$acct.err" "$blob" "$mp" "$cont" "$rec" "$wrec" "$f"; return
  fi
  apiv="$(cat "$acct.apiversion" 2>/dev/null || echo "${API_STORAGE%% *}")"
  ev="$(save_raw storage "$id" "$acct")"
  arm_get "$id/blobServices/default" "$blob" "$apiv"; rc=$?
  if [ $rc -ne 0 ]; then bst="$(rc_name $rc)"; echo 'null' > "$blob"; record_error storage blob-service "$id" "$bst" "$(err_msg "$blob")"; fi
  arm_get "$id/managementPolicies/default" "$mp" "$apiv"; rc=$?
  if [ $rc -eq $RC_NOTFOUND ]; then mst="NONE"; echo 'null' > "$mp"
  elif [ $rc -ne 0 ]; then mst="$(rc_name $rc)"; echo 'null' > "$mp"; record_error storage management-policy "$id" "$mst" "$(err_msg "$mp")"; fi
  arm_list "$id/blobServices/default/containers" "$cont" "$apiv"; rc=$?
  if [ $rc -ne 0 ]; then cst="$(rc_name $rc)"; echo '[]' > "$cont"; record_error storage containers "$id" "$cst" "$(err_msg "$cont")"
  else save_raw storage-containers "$id" "$cont" >/dev/null; fi
  # Fetch the container immutability policy explicitly when the list does not embed its state.
  if [ "$cst" = OK ]; then
    local fixed; fixed="$(tmpf)"; : > "$fixed"
    while IFS= read -r line; do
      cid="$(printf '%s' "$line" | jq -r .id)"
      if printf '%s' "$line" | jq -e '(.properties.hasImmutabilityPolicy // false) and (((.properties.immutabilityPolicy.properties.state // .properties.immutabilityPolicy.state) // "") == "")' >/dev/null 2>&1; then
        pol="$(tmpf)"
        if arm_get "$cid/immutabilityPolicies/default" "$pol" "$apiv"; then
          printf '%s' "$line" | jq -c --slurpfile p "$pol" '.properties.immutabilityPolicy = {properties: ($p[0].properties // {})}' >> "$fixed"
        else
          record_error storage immutability-policy "$cid" "$(rc_name $?)" "$(err_msg "$pol")"
          printf '%s' "$line" | jq -c '.properties.immutabilityPolicyUnreadable = true' >> "$fixed"
        fi
        rm -f "$pol" "$pol.err" "$pol.apiversion"
      else
        printf '%s\n' "$line" >> "$fixed"
      fi
    done < <(jq -c '.[]' "$cont")
    jq -s '.' "$fixed" > "$cont"; rm -f "$fixed"
  fi

  jqlib '
    $acct[0] as $a | ($a.properties // {}) as $p | ($blob[0].properties // {}) as $bp
    | [ $cont[0][] | container_worm($a; $cfg) + {unreadable: (.properties.immutabilityPolicyUnreadable // false)}
        | if .unreadable then .wormState = "BLOB_LEVEL_UNVERIFIED" | .wormCompliant = false else . end ] as $W
    | ([$W[] | select(.isLogContainer)]) as $logW
    | (if ($logW | length) > 0 then {basis: "LOG_CONTAINERS", set: $logW}
       elif ($W | length) > 0 then {basis: "ALL_CONTAINERS", set: $W}
       else {basis: "NO_CONTAINERS", set: []} end) as $E
    | ($p.immutableStorageWithVersioning // {}) as $vl
    | (if ($E.set | length) > 0 then ($E.set | map(.wormState) | min_by(worm_rank))
       elif ($vl.enabled // false) and (($vl.immutabilityPolicy.state // "") | lc) == "locked" then
         (if ($vl.immutabilityPolicy.immutabilityPeriodSinceCreationInDays // 0) >= $cfg.archiveMin then "LOCKED_AND_RETENTION_SUFFICIENT" else "LOCKED_IMMUTABILITY" end)
       elif ($vl.enabled // false) and (($vl.immutabilityPolicy.state // "") | lc) == "unlocked" then "UNLOCKED_IMMUTABILITY"
       elif ($vl.enabled // false) then "BLOB_LEVEL_UNVERIFIED"
       else "NO_IMMUTABILITY" end) as $agg
    | ([ ($mp[0].properties.policy.rules // [])[] | select(.enabled != false)
         | (.definition.filters.prefixMatch // []) as $pm
         | select(($pm | length) == 0 or ([$pm[] | split("/")[0]] as $cs | [$E.set[].container] | any(. as $c | $cs | index($c))))
         | (.definition.actions // {}) as $ac
         | [ $ac.baseBlob.delete.daysAfterModificationGreaterThan, $ac.baseBlob.delete.daysAfterCreationGreaterThan,
             $ac.baseBlob.delete.daysAfterLastAccessTimeGreaterThan, $ac.version.delete.daysAfterCreationGreaterThan ] | map(select(. != null)) | .[] ] | min) as $minDel
    | {
        id: ($a.id | lc), name: $a.name, subscriptionId: ($a.id | sub_of), subscriptionName: $subname, resourceGroup: ($a.id | rg_of),
        location: ($a.location // ""), kind: ($a.kind // ""), sku: ($a.sku.name // ""),
        auditStatus: "OK", auditError: "", blobServiceStatus: $bst, containersStatus: $cst, lifecycleStatus: $mst,
        referenced: $tgt.referenced, reasons: $tgt.reasons, referenceCount: $tgt.referenceCount,
        isHnsEnabled: ($p.isHnsEnabled // false), minimumTlsVersion: ($p.minimumTlsVersion // "TLS1_0"),
        supportsHttpsTrafficOnly: ($p.supportsHttpsTrafficOnly // true), publicNetworkAccess: ($p.publicNetworkAccess // "Enabled"),
        networkDefaultAction: ($p.networkAcls.defaultAction // "Allow"), allowBlobPublicAccess: ($p.allowBlobPublicAccess // false),
        allowSharedKeyAccess: ($p.allowSharedKeyAccess // true),
        blobVersioning: ($bp.isVersioningEnabled // false),
        blobSoftDelete: ($bp.deleteRetentionPolicy.enabled // false), blobSoftDeleteDays: ($bp.deleteRetentionPolicy.days // null),
        containerSoftDelete: ($bp.containerDeleteRetentionPolicy.enabled // false), containerSoftDeleteDays: ($bp.containerDeleteRetentionPolicy.days // null),
        changeFeed: ($bp.changeFeed.enabled // false), changeFeedRetentionDays: ($bp.changeFeed.retentionInDays // null),
        lifecycleRules: (($mp[0].properties.policy.rules // []) | length), lifecycleMinDeleteDays: $minDel,
        accountVersionLevelImmutability: ($vl.enabled // false),
        accountImmutabilityPolicyState: ($vl.immutabilityPolicy.state // null),
        accountImmutabilityPeriodDays: ($vl.immutabilityPolicy.immutabilityPeriodSinceCreationInDays // null),
        containersTotal: ($W | length), containersEvaluated: ($E.set | length), evaluationBasis: $E.basis,
        containerStates: ($E.set | map(.container + "=" + .wormState + (if .immutabilityPeriodDays != null then "(" + (.immutabilityPeriodDays | tostring) + "d," + .policyState + ")" else "" end)) | join("; ")),
        wormState: $agg, wormCompliant: ($agg == "LOCKED_AND_RETENTION_SUFFICIENT"),
        minImmutabilityDays: ([$E.set[].immutabilityPeriodDays | select(. != null)] | min),
        meetsTarget: (($E.set | length) > 0 and ($E.set | all(.meetsTarget))),
        evidenceFile: $ev
      }
    | ., ($W[] | . + {subscriptionName: $subname, evaluated: (.isLogContainer or $E.basis == "ALL_CONTAINERS"), recordType: "worm"})' \
    -c -n --slurpfile acct "$acct" --slurpfile blob "$blob" --slurpfile mp "$mp" --slurpfile cont "$cont" \
    --argjson tgt "$tgt" --argjson cfg "$STO_CFG" --arg bst "$bst" --arg cst "$cst" --arg mst "$mst" --arg subname "$subname" --arg ev "$ev" \
    > "$rec" 2>"$rec.err"
  if [ -s "$rec.err" ]; then log_error "internal: storage evaluation $id: $(head -c 300 "$rec.err")"; fi
  jq -c 'select(.recordType == "worm") | del(.recordType)' "$rec" >> "$SHARD_DIR/worm.jsonl"
  jq -c 'select(.recordType != "worm")' "$rec" > "$wrec"
  emit_file storage "$wrec"

  jqlib '
    . as $s | {subscriptionId: $s.subscriptionId, resourceId: $s.id, resourceType: "microsoft.storage/storageaccounts", resourceName: $s.name, evidenceFile: $s.evidenceFile} as $b
    | ("Referenced by: " + (if $s.referenced then ($s.reasons | join(", ")) else "none (matched ARCHIVE_STORAGE_REGEX only)" end)) as $ref
    | (if $s.referenced then 1 else 0 end) as $isRef
    | ("GET " + $s.id + "/blobServices/default/containers") as $how
    | ("Account default version-level policy: " + (if $s.accountVersionLevelImmutability then (($s.accountImmutabilityPolicyState // "none") + " " + (($s.accountImmutabilityPeriodDays // 0) | tostring) + "d") else "not enabled" end)
       + " | Evaluated (" + $s.evaluationBasis + "): " + (if $s.containerStates == "" then "none" else $s.containerStates end)) as $wev
    | ( if $s.isHnsEnabled then $b + {control: "ARC-002", status: "NOT_APPLICABLE", reason: "Hierarchical namespace (ADLS Gen2): blob versioning / version-level WORM not applicable; container-level WORM is evaluated"}
        elif $s.blobServiceStatus != "OK" then $b + {control: "ARC-002", status: "NOT_VERIFIABLE", severity: "LOW", reason: ("blobServices/default: " + $s.blobServiceStatus)}
        elif $s.blobVersioning then $b + {control: "ARC-002", status: "PASS", actual: "Blob versioning enabled"}
        else $b + {control: "ARC-002", status: "WARNING", severity: (if $isRef == 1 then "MEDIUM" else "LOW" end), actual: "Blob versioning disabled", evidence: $ref,
                   reason: "Versioning alone does not provide WORM, but supports recovery and version-level immutability."} end ),
      ( if $s.blobServiceStatus != "OK" then $b + {control: "ARC-003", status: "NOT_VERIFIABLE", severity: "LOW", reason: ("blobServices/default: " + $s.blobServiceStatus)}
        elif $s.blobSoftDelete and $s.containerSoftDelete then $b + {control: "ARC-003", status: "PASS", actual: ("Blob soft delete " + ($s.blobSoftDeleteDays | tostring) + "d, container soft delete " + ($s.containerSoftDeleteDays | tostring) + "d")}
        else $b + {control: "ARC-003", status: "WARNING", severity: (if $isRef == 1 then "MEDIUM" else "LOW" end),
                   actual: ("Blob soft delete=" + ($s.blobSoftDelete | tostring) + ", container soft delete=" + ($s.containerSoftDelete | tostring)), evidence: $ref,
                   recommendation: "Enable blob and container soft delete."} end ),
      ( if $s.containersStatus != "OK" then
          $b + {control: "ARC-004", status: (if $s.containersStatus == "FORBIDDEN" or $s.containersStatus == "AUTH" then "NOT_VERIFIABLE" else "ERROR" end),
                severity: "HIGH", reason: ("Container list not readable: " + $s.containersStatus), evidence: $ref}
        else
          ( if $s.wormState == "NO_IMMUTABILITY" then
              $b + {control: "ARC-004", status: (if $isRef == 1 then "FAIL" else "WARNING" end), severity: (if $isRef == 1 then "CRITICAL" else "MEDIUM" end),
                    expected: ("Locked time-based immutability >= " + ($cfg.archiveMin | tostring) + " days on log containers"),
                    actual: ("No immutability policy / legal hold. " + $wev), evidence: ($how + " | " + $ref),
                    reason: (if $isRef == 1 then "Archive destination receives security logs but no immutable copy exists." else "Account looks like a logging/archive account (name match) but has no WORM protection." end),
                    recommendation: "Configure a time-based retention policy (>= 1825 days, allowProtectedAppendWrites/All) on the log containers and lock it."}
            elif $s.wormState == "BLOB_LEVEL_UNVERIFIED" then
              $b + {control: "ARC-004", status: "NOT_VERIFIABLE", severity: "MEDIUM", actual: $wev, evidence: $how,
                    reason: "Version-level immutability enabled without a container/account default policy (or policy unreadable); blob-level policies are data-plane state not visible via ARM."}
            else $b + {control: "ARC-004", status: "PASS", actual: $wev, evidence: $how} end ),
          ( if $s.wormState == "UNLOCKED_IMMUTABILITY" then
              $b + {control: "ARC-005", status: (if $isRef == 1 then "FAIL" else "WARNING" end), severity: "HIGH", expected: "Immutability policy state Locked",
                    actual: ("Unlocked policy (can be shortened or deleted by an administrator). " + $wev), evidence: ($how + " | " + $ref),
                    reason: "An unlocked immutability policy does not satisfy WORM requirements.",
                    recommendation: "Lock the policy after validation (irreversible)."}
            elif $s.wormState == "LEGAL_HOLD" then
              $b + {control: "ARC-005", status: "WARNING", severity: "MEDIUM", actual: ("Legal hold only (no locked time-based policy). " + $wev), evidence: $how,
                    reason: "Legal holds are removable and not a retention policy."}
            elif $s.wormState == "LOCKED_IMMUTABILITY" or $s.wormState == "LOCKED_AND_RETENTION_SUFFICIENT" then
              $b + {control: "ARC-005", status: "PASS", actual: $wev, evidence: $how}
            elif $s.wormState == "BLOB_LEVEL_UNVERIFIED" then $b + {control: "ARC-005", status: "NOT_VERIFIABLE", severity: "MEDIUM", actual: $wev}
            else $b + {control: "ARC-005", status: "NOT_APPLICABLE", reason: "No immutability policy (see ARC-004)"} end ),
          ( if $s.wormState == "LOCKED_AND_RETENTION_SUFFICIENT" then
              $b + {control: "ARC-006", status: "PASS", expected: (">= " + ($cfg.archiveMin | tostring) + " days"), actual: ("Minimum locked period " + ($s.minImmutabilityDays // $s.accountImmutabilityPeriodDays | tostring) + " days"), evidence: $wev}
            elif $s.wormState == "LOCKED_IMMUTABILITY" then
              $b + {control: "ARC-006", status: (if $isRef == 1 then "FAIL" else "WARNING" end), severity: "MEDIUM", expected: (">= " + ($cfg.archiveMin | tostring) + " days locked retention"),
                    actual: ("Locked period below minimum. " + $wev), evidence: ($how + " | " + $ref), recommendation: "Extend the locked policy period (extension is allowed on locked policies)."}
            elif $s.wormState == "UNLOCKED_IMMUTABILITY" then
              $b + {control: "ARC-006", status: (if (($s.minImmutabilityDays // 0) < $cfg.archiveMin) and $isRef == 1 then "FAIL" else "WARNING" end), severity: "MEDIUM",
                    expected: (">= " + ($cfg.archiveMin | tostring) + " days locked retention"), actual: ("Unlocked policy, period " + (($s.minImmutabilityDays // 0) | tostring) + " days. " + $wev)}
            elif $s.wormState == "BLOB_LEVEL_UNVERIFIED" then $b + {control: "ARC-006", status: "NOT_VERIFIABLE", severity: "MEDIUM", actual: $wev}
            else $b + {control: "ARC-006", status: "NOT_APPLICABLE", reason: ("No time-based policy (" + $s.wormState + ")")} end ),
          ( if $s.wormState == "LOCKED_AND_RETENTION_SUFFICIENT" then
              (if $s.meetsTarget then $b + {control: "ARC-007", status: "PASS", actual: ("Locked retention >= " + ($cfg.archiveTarget | tostring) + " days")}
               else $b + {control: "ARC-007", status: "WARNING", severity: "LOW", expected: (">= " + ($cfg.archiveTarget | tostring) + " days (6 years)"),
                          actual: ("Minimum locked period " + (($s.minImmutabilityDays // $s.accountImmutabilityPeriodDays // 0) | tostring) + " days")} end)
            else empty end )
        end ),
      ( if $s.lifecycleStatus == "NONE" then $b + {control: "ARC-008", status: "PASS", actual: "No lifecycle management policy"}
        elif $s.lifecycleStatus != "OK" then $b + {control: "ARC-008", status: "NOT_VERIFIABLE", severity: "LOW", reason: ("managementPolicies/default: " + $s.lifecycleStatus)}
        elif ($s.lifecycleMinDeleteDays != null) and ($s.lifecycleMinDeleteDays < $cfg.archiveMin) then
          $b + {control: "ARC-008", status: "WARNING", severity: "MEDIUM", expected: ("No lifecycle deletion before " + ($cfg.archiveMin | tostring) + " days"),
                actual: ("Lifecycle rule deletes log blobs after " + ($s.lifecycleMinDeleteDays | tostring) + " days"), evidence: ("GET " + $s.id + "/managementPolicies/default"),
                reason: "Deletion is blocked while a WORM policy is active, but the lifecycle intent conflicts with the 5-6 year archive requirement."}
        else $b + {control: "ARC-008", status: "PASS", actual: ("Lifecycle rules=" + ($s.lifecycleRules | tostring) + ", earliest delete " + (($s.lifecycleMinDeleteDays // "never") | tostring))} end ),
      ( ([ (if ($s.minimumTlsVersion | test("TLS1_[23]") | not) then "minimumTlsVersion=" + $s.minimumTlsVersion else empty end),
           (if ($s.supportsHttpsTrafficOnly | not) then "HTTP (non-TLS) allowed" else empty end),
           (if $s.publicNetworkAccess != "Disabled" and $s.networkDefaultAction == "Allow" then "public network access from all networks" else empty end) ]) as $iss
        | if ($iss | length) > 0 then $b + {control: "ARC-009", status: "WARNING", severity: (if ($iss | map(test("TLS|HTTP ")) | any) then "MEDIUM" else "LOW" end), actual: ($iss | join(", "))}
          else $b + {control: "ARC-009", status: "PASS", actual: ("TLS " + $s.minimumTlsVersion + ", HTTPS only, network " + $s.networkDefaultAction + "/" + $s.publicNetworkAccess)} end ),
      ( if $s.isHnsEnabled then $b + {control: "ARC-010", status: "NOT_APPLICABLE", reason: "Change feed support is limited for hierarchical-namespace accounts"}
        elif $s.blobServiceStatus != "OK" then empty
        elif $s.changeFeed then $b + {control: "ARC-010", status: "PASS", actual: ("Change feed enabled, retention " + (($s.changeFeedRetentionDays // "unlimited") | tostring))}
        else $b + {control: "ARC-010", status: "WARNING", severity: "LOW", actual: "Change feed disabled", reason: "Change feed provides a tamper-evident record of blob changes."} end ),
      ( ([$worm0[] | select(.recordType == "worm" and .storageAccountId == $s.id and (.container | test("^insights-")) and (.policyState | lc) == "locked"
                           and ((.allowProtectedAppendWrites // false) | not) and ((.allowProtectedAppendWritesAll // false) | not))]) as $np
        | if ($s.reasons | index("diagnosticSetting") or index("activityLog") or index("entra")) and ($np | length) > 0 then
            $b + {control: "ARC-011", status: "WARNING", severity: "LOW", actual: ("Locked diagnostic containers without allowProtectedAppendWrites(All): " + ($np | map(.container) | join(", "))),
                  reason: "Azure Monitor writes diagnostic logs as append blobs; verify that writes into these containers succeed."}
          else empty end ),
      ( ([ (if $s.allowSharedKeyAccess then "shared key access enabled" else empty end),
           (if $s.allowBlobPublicAccess then "anonymous blob public access allowed" else empty end) ]) as $iss
        | if ($iss | length) > 0 then $b + {control: "ARC-012", status: "WARNING", severity: (if $s.allowBlobPublicAccess then "MEDIUM" else "LOW" end), actual: ($iss | join(", "))}
          else $b + {control: "ARC-012", status: "PASS", actual: "Shared key and anonymous access disabled"} end )' \
    -c --argjson cfg "$STO_CFG" --slurpfile worm0 "$rec" "$wrec" > "$f"
  ingest_findings "$f"
  rm -f "$acct" "$acct.apiversion" "$acct.err" "$blob" "$blob.err" "$blob.apiversion" "$mp" "$mp.err" "$mp.apiversion" \
        "$cont" "$cont.err" "$cont.apiversion" "$rec" "$rec.err" "$wrec" "$f"
}

build_sto_cfg() {
  STO_CFG="$(jq -nc --argjson archiveMin "$ARCHIVE_RETENTION_MIN_DAYS" --argjson archiveTarget "$ARCHIVE_RETENTION_TARGET_DAYS" \
     --arg logContainerRegex "$LOG_CONTAINER_REGEX" '{archiveMin: $archiveMin, archiveTarget: $archiveTarget, logContainerRegex: $logContainerRegex}')"
}

# Event Hub namespaces referenced as destinations but outside the inventoried
# subscriptions are audited by ID so the LAW -> EH path can still be verified.
ensure_referenced_eventhubs() {
  local law diag act eh id
  law="$(merged law)"; diag="$(merged diagnostic)"; act="$(merged activity)"; eh="$(merged eventhubs)"
  jq -rn --slurpfile l "$law" --slurpfile d "$diag" --slurpfile a "$act" --slurpfile e "$eh" '
    ([$e[] | select(.kind == "namespace") | .id]) as $known
    | ([$l[] | .eventHubDestinations[]? | .namespaceId] + [$d[] | .eventHubNamespaces[]?] + [$a[] | .eventHubNamespaces[]?])
    | map(ascii_downcase) | unique | map(select(. as $x | ($known | index($x)) == null)) | .[]' 2>/dev/null |
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    log_info "Auditing referenced Event Hub namespace outside inventory: $(printf '%s' "$id" | awk -F/ '{print $NF}')"
    audit_eventhub_namespace "$id" "" true
  done
}

# =============================================================================
# RBAC ON LOGGING INFRASTRUCTURE
# API: GET {scope}/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()
#          (assignments at the scope and inherited from above; api 2022-04-01)
#      GET {scope}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?$filter=atScope()
#      GET /subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions
#      GET {graph}/v1.0/groups/{id} | servicePrincipals/{id}   (display names; users are never resolved)
# Effective permissions (deny assignments, group nesting, PIM activation, ABAC
# conditions) are NOT computed; the report shows assignments only.
# =============================================================================
audit_rbac() {
  if [ "$OPT_SKIP_RBAC" = true ]; then log_info "RBAC audit skipped (--skip-rbac)"; return; fi
  local law eh sto line sub n
  law="$(merged law)"; eh="$(merged eventhubs)"; sto="$(merged storage)"
  jq -cn --slurpfile l "$law" --slurpfile e "$eh" --slurpfile s "$sto" '
    ([$l[] | select(.auditStatus == "OK") | .eventHubDestinations[]? | .namespaceId]) as $expNs
    | [ ($l[] | select(.auditStatus == "OK") | {scope: .id, scopeType: "LogAnalyticsWorkspace", name: .name}),
        ($e[] | select(.kind == "namespace" and .auditStatus == "OK" and (.isSecurityStream or (.id as $i | $expNs | index($i)))) | {scope: .id, scopeType: "EventHubNamespace", name: .name}),
        ($s[] | select(.auditStatus == "OK" and .referenced) | {scope: .id, scopeType: "ArchiveStorage", name: .name}) ]
    | (. + map({scope: (.scope | capture("^(?<rg>/subscriptions/[^/]+/resourcegroups/[^/]+)"; "i").rg | ascii_downcase), scopeType: "ResourceGroup",
                name: (.scope | capture("/resourcegroups/(?<n>[^/]+)"; "i").n)}))
    | unique_by(.scope) | .[] | . + {subscriptionId: (.scope | split("/")[2])}' > "$WORK/rbac_scopes.jsonl"
  n="$(wc -l < "$WORK/rbac_scopes.jsonl" | tr -d ' ')"
  log_info "Auditing RBAC on $n logging scope(s)..."
  [ "$n" -gt 0 ] || return
  # Role definitions per subscription (built-in + custom), cached.
  for sub in $(jq -r '.subscriptionId' "$WORK/rbac_scopes.jsonl" | sort -u); do
    pool_run fetch_role_definitions "$sub"
  done
  pool_wait
  while IFS= read -r line; do pool_run audit_rbac_scope "$line"; done < "$WORK/rbac_scopes.jsonl"
  pool_wait
  finalize_rbac
}

fetch_role_definitions() { # <sub>
  local out="$WORK/cache/roledefs/$1.json" rc
  get_all_pages "$(arm_url "/subscriptions/$1/providers/Microsoft.Authorization/roleDefinitions" "$API_AUTH")" "$out.tmp"; rc=$?
  if [ $rc -ne 0 ]; then record_error rbac role-definitions "/subscriptions/$1" "$(rc_name $rc)" "$(err_msg "$out.tmp")" "$1"; echo '[]' > "$out"
  else mv -f "$out.tmp" "$out"; fi
  rm -f "$out.tmp.err"
}

audit_rbac_scope() { # <scope json>
  local s="$1" scope ra pim rc st="OK" pst="OK" er=""
  scope="$(printf '%s' "$s" | jq -r .scope)"
  ra="$(tmpf)"; pim="$(tmpf)"
  get_all_pages "$(arm_url "$scope/providers/Microsoft.Authorization/roleAssignments?%24filter=atScope%28%29" "$API_AUTH")" "$ra"; rc=$?
  if [ $rc -ne 0 ]; then st="$(rc_name $rc)"; er="$(err_msg "$ra")"; echo '[]' > "$ra"; record_error rbac role-assignments "$scope" "$st" "$er"; fi
  get_all_pages "$(arm_url "$scope/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?%24filter=atScope%28%29" "$API_PIM")" "$pim"; rc=$?
  if [ $rc -ne 0 ]; then pst="$(rc_name $rc)"; echo '[]' > "$pim"; fi
  jq -cn --argjson s "$s" --slurpfile ra "$ra" --slurpfile pim "$pim" --arg st "$st" --arg er "$er" --arg pst "$pst" '
    ($s.scope | ascii_downcase) as $t
    | def inh($x): ($x // "" | ascii_downcase) as $a
        | if $a == $t then "DIRECT"
          elif $a == "/" then "INHERITED_ROOT"
          elif ($a | test("^/providers/microsoft\\.management/managementgroups/")) then "INHERITED_MANAGEMENT_GROUP"
          elif ($a | test("^/subscriptions/[^/]+$")) then "INHERITED_SUBSCRIPTION"
          elif ($a | test("^/subscriptions/[^/]+/resourcegroups/[^/]+$")) and ($t | startswith($a + "/")) then "INHERITED_RESOURCE_GROUP"
          elif ($t | startswith($a + "/")) then "INHERITED_PARENT"
          else "OTHER_SCOPE" end;
    {scopeRecord: ($s + {assignmentsStatus: $st, assignmentsError: $er, eligibilityStatus: $pst})},
    ($ra[0][] | .properties as $p | {scope: $t, scopeType: $s.scopeType, scopeName: $s.name, subscriptionId: $s.subscriptionId,
        assignmentType: "ACTIVE", assignmentId: .id, assignmentScope: $p.scope, inheritance: inh($p.scope),
        principalId: $p.principalId, principalType: ($p.principalType // "Unknown"), roleDefinitionId: $p.roleDefinitionId,
        hasCondition: (($p.condition // "") != "")}),
    ($pim[0][] | .properties as $p | {scope: $t, scopeType: $s.scopeType, scopeName: $s.name, subscriptionId: $s.subscriptionId,
        assignmentType: "ELIGIBLE", assignmentId: .id, assignmentScope: $p.scope, inheritance: inh($p.scope),
        principalId: $p.principalId, principalType: ($p.principalType // "Unknown"), roleDefinitionId: $p.roleDefinitionId,
        hasCondition: (($p.condition // "") != ""), memberType: ($p.memberType // null)})' >> "$SHARD_DIR/rbac_raw.jsonl"
  rm -f "$ra" "$ra.err" "$pim" "$pim.err"
}

resolve_principal() { # <principalId> <principalType>
  local id="$1" type="$2" out="$WORK/cache/principal/$1.json" t rc path
  [ -s "$out" ] && return 0
  case "$type" in
    Group) path="groups/$id?%24select=id,displayName" ;;
    ServicePrincipal) path="servicePrincipals/$id?%24select=id,displayName,appId,servicePrincipalType" ;;
    *) return 0 ;;
  esac
  t="$(tmpf)"
  az_call get "$GRAPH/v1.0/$path" "$t"; rc=$?
  if [ $rc -eq 0 ]; then jq -c '{id, displayName: (.displayName // ""), status: "OK"}' "$t" > "$out"
  else jq -nc --arg id "$id" --arg st "$(rc_name $rc)" '{id: $id, displayName: "", status: $st}' > "$out"; fi
  rm -f "$t" "$t.err"
}

finalize_rbac() {
  local raw p id type
  raw="$(merged rbac_raw)"
  # Role definitions not found in subscription lists are fetched by full ID.
  jq -s 'map(.[]) | map({key: (.name | ascii_downcase), value: .}) | from_entries' "$WORK"/cache/roledefs/*.json > "$WORK/roledefs.json" 2>/dev/null || echo '{}' > "$WORK/roledefs.json"
  jq -r --slurpfile d "$WORK/roledefs.json" 'select(.roleDefinitionId != null) | .roleDefinitionId as $r | ($r | split("/") | last | ascii_downcase) as $g | select($d[0][$g] == null) | $r' "$raw" | sort -u |
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    p="$(tmpf)"
    if arm_get "$id" "$p" "$API_AUTH"; then
      jq -c '{(.name | ascii_downcase): .}' "$p" >> "$WORK/roledefs.extra.jsonl"
    fi
    rm -f "$p" "$p.err" "$p.apiversion"
  done
  if [ -s "$WORK/roledefs.extra.jsonl" ]; then
    jq -s 'add' "$WORK/roledefs.json" "$WORK/roledefs.extra.jsonl" > "$WORK/roledefs.json.tmp" && mv -f "$WORK/roledefs.json.tmp" "$WORK/roledefs.json"
  fi
  if [ "$RESOLVE_PRINCIPAL_NAMES" = true ]; then
    while IFS=$'\t' read -r id type; do
      [ -n "$id" ] || continue
      pool_run resolve_principal "$id" "$type"
    done < <(jq -r 'select(.principalId != null and (.principalType == "Group" or .principalType == "ServicePrincipal")) | "\(.principalId)\t\(.principalType)"' "$raw" | sort -u)
    pool_wait
  fi
  cat "$WORK"/cache/principal/*.json 2>/dev/null | jq -s 'map({key: .id, value: .}) | from_entries' > "$WORK/principals.json" || echo '{}' > "$WORK/principals.json"
  [ -s "$WORK/principals.json" ] || echo '{}' > "$WORK/principals.json"

  local rec f
  rec="$(tmpf)"; f="$(tmpf)"
  jqlib '
    select(.scopeRecord == null)
    | . as $a | ($a.roleDefinitionId // "" | split("/") | last | ascii_downcase) as $g
    | ($defs[0][$g] // null) as $rd
    | ($pr[0][$a.principalId // ""] // null) as $pn
    | $a + {roleName: ($rd.properties.roleName // "unknown"), roleType: ($rd.properties.type // "unknown"),
            roleClass: (if $rd == null then "UNKNOWN" else ($rd | role_class) end),
            principalDisplayName: (if ($a.principalType == "Group" or $a.principalType == "ServicePrincipal") then ($pn.displayName // "") else "" end),
            principalNameStatus: ($pn.status // (if ($a.principalType == "Group" or $a.principalType == "ServicePrincipal") then "NOT_RESOLVED" else "NOT_RESOLVED_BY_DESIGN" end))}
    | . + {privileged: ((.roleClass | IN("ADMIN", "WRITE", "DATA_WRITE")) or ((.roleName | lc) as $rn | ($cfg.privilegedRoles | split("|") | map(lc) | index($rn)) != null)),
           allowlisted: ((.principalId | rx($cfg.allowRegex)) or (.principalDisplayName | rx($cfg.allowRegex))),
           expectedReaderGroup: (.principalType == "Group" and (.principalDisplayName | rx($cfg.readerGroupsRegex)))}' \
    -c --slurpfile defs "$WORK/roledefs.json" --slurpfile pr "$WORK/principals.json" --argjson cfg "$RBAC_CFG" "$raw" > "$rec"
  emit_file rbac "$rec"
  jq -c 'select(.scopeRecord != null) | .scopeRecord' "$raw" >> "$SHARD_DIR/rbac_scopes.jsonl"

  jqlib '
    ($scopes | map({key: .scope, value: .}) | from_entries) as $S
    | group_by(.scope)[] as $grp
    | ($grp[0].scope) as $sc | ($S[$sc] // {}) as $srec
    | {resourceId: $sc, resourceType: $grp[0].scopeType, resourceName: $grp[0].scopeName, subscriptionId: $grp[0].subscriptionId} as $b
    | ($grp | map(select(.privileged and (.allowlisted | not)))) as $priv
    | ($priv | map(select(.inheritance == "DIRECT" or .inheritance == "INHERITED_RESOURCE_GROUP"))) as $near
    | (def fmt: map(.roleName + " @" + (if .inheritance == "DIRECT" then "this scope" else .inheritance end) + " -> " + .principalType + ":" + .principalId
                   + (if .principalDisplayName != "" then " (" + .principalDisplayName + ")" else "" end) + (if .assignmentType == "ELIGIBLE" then " [PIM eligible]" else "" end)) | join("; ");
       ( if ($priv | length) == 0 then $b + {control: "RBAC-001", status: "PASS", actual: ("No non-allowlisted write/admin assignments (" + ($grp | length | tostring) + " assignments reviewed)")}
         else $b + {control: "RBAC-001", status: "WARNING",
                    severity: (if ($near | map(select(.roleClass == "ADMIN" or (.principalType == "User" and .roleClass == "WRITE"))) | length) > 0 then "HIGH" else "MEDIUM" end),
                    expected: "Read-only (Data Reader) access for consumers; write/admin limited to allow-listed platform principals",
                    actual: ("Write/admin assignments (" + ($priv | length | tostring) + "): " + ($priv | fmt)),
                    reason: "Assignments listed as configured; effective permissions (deny assignments, group nesting, PIM activation, conditions) are not computed.",
                    recommendation: "Remove unnecessary write/admin access or add platform principals to ALLOWED_PRIVILEGED_PRINCIPALS_REGEX."} end ),
       ( ($grp | map(select(.expectedReaderGroup))) as $rg
         | if ($rg | length) == 0 then empty
           elif ($rg | map(select(.roleClass | IN("ADMIN", "WRITE", "DATA_WRITE"))) | length) > 0 then
             $b + {control: "RBAC-002", status: "FAIL", severity: "HIGH", expected: "DEV / DATA / General Reader groups hold read-only (Data Reader) roles",
                   actual: ($rg | map(select(.roleClass | IN("ADMIN", "WRITE", "DATA_WRITE"))) | fmt)}
           else $b + {control: "RBAC-002", status: "PASS", actual: ($rg | fmt)} end ),
       ( if $grp[0].scopeType != "LogAnalyticsWorkspace" then empty
         else ($grp | map(select(.expectedReaderGroup and (.roleClass | IN("READ", "DATA_READ"))))) as $ok
           | ($grp | map(select(.principalType == "Group" and .principalNameStatus != "OK"))) as $unres
           | if ($ok | length) > 0 then $b + {control: "RBAC-003", status: "PASS", actual: ($ok | map(.principalDisplayName + " -> " + .roleName) | unique | join("; "))}
             elif ($unres | length) > 0 then $b + {control: "RBAC-003", status: "NOT_VERIFIABLE", severity: "LOW",
                    reason: ((($unres | length) | tostring) + " group principal name(s) could not be resolved via Microsoft Graph; expected-group matching not possible")}
             else $b + {control: "RBAC-003", status: "WARNING", severity: "MEDIUM", expected: ("Groups matching " + $cfg.readerGroupsRegex + " with reader roles"),
                        actual: "No expected reader group assignment found on this workspace (including inherited)"} end
         end ))' -s -c --argjson cfg "$RBAC_CFG" --argjson scopes "$(jq -sc '.' "$(merged rbac_scopes)")" "$rec" > "$f"
  ingest_findings "$f"
  # Scopes whose assignments could not be read
  jq -c 'select(.assignmentsStatus != "OK") | {resourceId: .scope, resourceType: .scopeType, resourceName: .name, subscriptionId,
         control: "RBAC-001", status: (if .assignmentsStatus == "FORBIDDEN" or .assignmentsStatus == "AUTH" then "NOT_VERIFIABLE" else "ERROR" end),
         severity: "MEDIUM", reason: ("roleAssignments not readable: " + .assignmentsStatus + " " + .assignmentsError)}' "$(merged rbac_scopes)" > "$f"
  ingest_findings "$f"
  rm -f "$rec" "$f"
}

build_rbac_cfg() {
  RBAC_CFG="$(jq -nc --arg privilegedRoles "$PRIVILEGED_ROLES" --arg allowRegex "$ALLOWED_PRIVILEGED_PRINCIPALS_REGEX" \
     --arg readerGroupsRegex "$EXPECTED_READER_GROUPS_REGEX" '{privilegedRoles: $privilegedRoles, allowRegex: $allowRegex, readerGroupsRegex: $readerGroupsRegex}')"
}

# =============================================================================
# OPTIONAL CRIBL VERIFICATION (read-only GET; token never printed or stored)
# GET {CRIBL_API_URL}/api/v1[/m/{group}]/system/inputs
# =============================================================================
verify_cribl() {
  local out="$WORK/cribl.json" raw code url
  if [ -z "$CRIBL_API_URL" ] || [ -z "$CRIBL_API_TOKEN" ]; then
    echo '{"configured": false}' > "$out"; return
  fi
  log_info "Querying Cribl API for Event Hub inputs (optional verification)..."
  raw="$(tmpf)"
  url="${CRIBL_API_URL%/}/api/v1${CRIBL_WORKER_GROUP:+/m/$CRIBL_WORKER_GROUP}/system/inputs"
  code="$(printf 'Authorization: Bearer %s\n' "$CRIBL_API_TOKEN" | curl -sS --max-time 60 -H @- -H 'Accept: application/json' -o "$raw" -w '%{http_code}' "$url" 2>"$raw.err")" || code="000"
  if [ "$code" = 200 ] && jq empty "$raw" >/dev/null 2>&1; then
    jq -c '{configured: true, status: "OK", inputs: [(.items // .)[]? | select(((.type // "") | test("eventhub|event_hub|azure"; "i")))
            | {id: (.id // ""), type: (.type // ""), disabled: (.disabled // false), brokers: (.brokers // []), topics: (.topics // []), groupId: (.groupId // "")}]}' "$raw" > "$out"
  else
    jq -nc --arg c "$code" --arg e "$(tr '\n' ' ' < "$raw.err" | cut -c1-200)" '{configured: true, status: (if $c == "401" or $c == "403" then "FORBIDDEN" else "ERROR" end), httpCode: $c, error: $e, inputs: []}' > "$out"
    record_error cribl system-inputs "$CRIBL_API_URL" "HTTP_$code" "Cribl API request failed"
  fi
  rm -f "$raw" "$raw.err"
}

# =============================================================================
# CORRELATION (cross-resource controls; evaluated once all evidence exists)
# =============================================================================
correlate() {
  log_info "Correlating architecture paths (LAW -> Event Hub -> Cribl, archives, Entra, databases, UWWB)..."
  local diag act entra law lt eh sto db dbx appi inv f
  diag="$(merged diagnostic)"; act="$(merged activity)"; entra="$(merged entra)"; law="$(merged law)"
  lt="$(merged law_tables)"; eh="$(merged eventhubs)"; sto="$(merged storage)"
  db="$(merged databases)"; dbx="$(merged databricks)"; appi="$(merged appinsights)"; inv="$(merged resources)"
  f="$(tmpf)"
  local common=(--slurpfile diag "$diag" --slurpfile act "$act" --slurpfile entra "$entra" --slurpfile law "$law"
                --slurpfile lt "$lt" --slurpfile eh "$eh" --slurpfile sto "$sto" --slurpfile db "$db" --slurpfile dbx "$dbx"
                --slurpfile appi "$appi" --slurpfile inv "$inv" --slurpfile worm "$(merged worm)" --slurpfile cribl "$WORK/cribl.json" --argjson cfg "$CORR_CFG")
  jqlib '
    def smap: ($sto | map({key: .id, value: .}) | from_entries);
    ($worm | map({key: (.storageAccountId + "|" + (.container | lc)), value: .}) | from_entries) as $WM
    # WORM state of the containers a given log flow actually writes to (Azure Monitor
    # naming: insights-logs-<category>, insights-activity-logs, am-<table>). A container
    # that does not exist yet inherits only the account default version-level policy.
    | def flow_state($m; $acct; $conts):
        ($m[$acct] // null) as $s
        | if $s == null then {name: ($acct | name_of), state: "NOT_AUDITED", detail: "not audited"}
          elif $s.auditStatus != "OK" then {name: $s.name, state: $s.auditStatus, detail: ($s.auditError // "")}
          elif ($s.containersStatus // "OK") != "OK" then {name: $s.name, state: "NOT_VERIFIABLE", detail: ("containers " + $s.containersStatus)}
          else
            ( if $s.accountVersionLevelImmutability and (($s.accountImmutabilityPolicyState // "") | lc) == "locked" then
                (if ($s.accountImmutabilityPeriodDays // 0) >= $cfg.archiveMin then "LOCKED_AND_RETENTION_SUFFICIENT" else "LOCKED_IMMUTABILITY" end)
              elif $s.accountVersionLevelImmutability and (($s.accountImmutabilityPolicyState // "") | lc) == "unlocked" then "UNLOCKED_IMMUTABILITY"
              elif $s.accountVersionLevelImmutability then "BLOB_LEVEL_UNVERIFIED"
              else "NO_IMMUTABILITY" end ) as $acctDefault
            | [ $conts[] | (. | lc) as $c | ($WM[$acct + "|" + $c] // null) as $w
                | if $w != null then {c: $c, state: $w.wormState, missing: false} else {c: $c, state: $acctDefault, missing: true} end ] as $X
            | {name: $s.name, state: ($X | map(.state) | min_by(worm_rank)),
               detail: ($X | map(.c + "=" + .state + (if .missing then "(container not created yet; account default)" else "" end)) | join(", "))}
          end;
      def archive_verdict($m; $ids; $conts):
        [ $ids[] | flow_state($m; .; (if ($conts | length) == 0 then ["insights-logs"] else $conts end)) ] as $A
        | ($A | map(.name + " [" + .detail + "]") | join("; ")) as $txt
        | if ($A | length) == 0 then {status: "NONE", text: "no Storage destination"}
          elif ($A | map(select(.state == "LOCKED_AND_RETENTION_SUFFICIENT")) | length) > 0 then {status: "PASS", text: $txt}
          elif ($A | map(select((.state | IN("NO_IMMUTABILITY", "UNLOCKED_IMMUTABILITY", "LOCKED_IMMUTABILITY", "LEGAL_HOLD")) | not)) | length) > 0 then {status: "NOT_VERIFIABLE", text: $txt}
          else ($A | map(.state | worm_rank) | max) as $best
            | {status: (if $best == 4 then "WARNING" else "FAIL" end), best: $best,
               severity: (if $best >= 3 then "MEDIUM" else "HIGH" end), text: $txt} end;
      def diag_containers: (.categoriesToStorage // []) | map("insights-logs-" + lc);
    def lawmap: ($law | map({key: .id, value: .}) | from_entries);
    def ehns: ($eh | map(select(.kind == "namespace")) | map({key: .id, value: .}) | from_entries);
    def exported_via_law($wsIds; $table):
      [ $wsIds[] | . as $w | (lawmap[$w] // null) | if . == null then {ws: ($w | name_of), state: "OUT_OF_SCOPE"}
        elif .auditStatus != "OK" or .exportsStatus != "OK" then {ws: .name, state: "NOT_VERIFIABLE"}
        elif ((.exportedToEventHub | map(lc)) | index($table | lc)) != null then {ws: .name, state: "EXPORTED"}
        else {ws: .name, state: "NOT_EXPORTED"} end ];
    def active_in($table): [ $lt[] | select(.active == true and ((.table | lc) == ($table | lc))) | .workspaceName ] | unique;
    (smap) as $SM | (lawmap) as $LM | (ehns) as $NS

    # ---- LOG-005: resource archive destinations are WORM compliant ----
    | ( $diag[] | select(.auditStatus == "OK" and ((.storageAccounts // []) | length) > 0) | . as $r
        | archive_verdict($SM; $r.storageAccounts; ($r | diag_containers)) as $v
        | ($r | fbase) + {control: "LOG-005",
            status: $v.status, severity: (if $v.status == "FAIL" and ($v.best // 5) == 0 and $r.isProd and $r.isCritical then "CRITICAL" else ($v.severity // "MEDIUM") end),
            expected: ("Storage destination with locked immutability >= " + ($cfg.archiveMin | tostring) + " days"),
            actual: ("Storage destination(s): " + $v.text),
            reason: (if $v.status == "NOT_VERIFIABLE" then "Archive storage account(s) could not be fully inspected" else "" end)} ),

    # ---- ACT-002 / ACT-003: Activity Log archive and streaming ----
    ( $act[] | select(.auditStatus == "OK" and .settingsCount > 0) | . as $a
      | {subscriptionId: $a.subscriptionId, resourceId: ("/subscriptions/" + $a.subscriptionId), resourceType: "microsoft.resources/subscriptions", resourceName: $a.subscriptionName, evidenceFile: $a.evidenceFile} as $b
      | ( archive_verdict($SM; $a.storageAccounts; ["insights-activity-logs"]) as $v
          | if $v.status == "NONE" then $b + {control: "ACT-002", status: "FAIL", severity: "HIGH", expected: ("Activity Logs archived to locked WORM storage >= " + ($cfg.archiveMin | tostring) + " days"),
                                               actual: ("No Storage destination. Settings: " + $a.settingsSummary), reason: "No long-term immutable copy of the subscription audit trail."}
            elif $v.status == "PASS" and (($a.requiredNotToStorage | length) > 0) then
              $b + {control: "ACT-002", status: "WARNING", severity: "MEDIUM", actual: ("WORM archive " + $v.text + " but categories not archived: " + ($a.requiredNotToStorage | join(", ")))}
            else $b + {control: "ACT-002", status: $v.status, severity: ($v.severity // "HIGH"), expected: "Locked WORM archive", actual: ("Storage destination(s): " + $v.text)} end ),
        ( if ($a.requiredNotToEventHub | length) == 0 then
            $b + {control: "ACT-003", status: "PASS", actual: ("Streamed directly to Event Hub " + ($a.eventHubNamespaces | map(name_of) | join(", ")))}
          else exported_via_law($a.workspaces; "AzureActivity") as $x
            | if ($x | map(select(.state == "EXPORTED")) | length) > 0 then
                $b + {control: "ACT-003", status: "PASS", actual: ("AzureActivity exported to Event Hub via LAW Data Export (" + ($x | map(select(.state == "EXPORTED") | .ws) | join(", ")) + ")")}
              elif ($x | map(select(.state == "NOT_VERIFIABLE" or .state == "OUT_OF_SCOPE")) | length) > 0 then
                $b + {control: "ACT-003", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: ("LAW export state not verifiable: " + ($x | map(.ws + "=" + .state) | join(", ")))}
              else
                $b + {control: "ACT-003", status: "FAIL", severity: "MEDIUM", expected: "Activity Log reaches the SOC Event Hub (direct or via LAW Data Export of AzureActivity)",
                      actual: ("No direct Event Hub destination; AzureActivity not exported from: " + ($x | map(.ws) | join(", ")))} end
          end ) ),

    # ---- ENTRA-001..008 ----
    ( ($entra[0] // {auditStatus: "SKIPPED", auditError: "not run"}) as $e
      | {resourceId: "/providers/microsoft.aadiam", resourceType: "microsoft.aadiam/diagnosticsettings", resourceName: "Entra ID tenant diagnostic settings", subscriptionId: "", evidenceFile: ($e.evidenceFile // "")} as $b
      | ([["AuditLogs","ENTRA-001","AuditLogs","HIGH"],["SignInLogs","ENTRA-002","SigninLogs","HIGH"],
          ["NonInteractiveUserSignInLogs","ENTRA-003","AADNonInteractiveUserSignInLogs","MEDIUM"],
          ["ServicePrincipalSignInLogs","ENTRA-004","AADServicePrincipalSignInLogs","MEDIUM"],
          ["ManagedIdentitySignInLogs","ENTRA-005","AADManagedIdentitySignInLogs","MEDIUM"],
          ["ProvisioningLogs","ENTRA-006","AADProvisioningLogs","MEDIUM"]]) as $M
      | ( $M[] as [$cat, $ctl, $tbl, $sev]
          | active_in($tbl) as $seen
          | if $e.auditStatus == "OK" then
              if (($e.categoriesToLaw // []) | map(lc) | index($cat | lc)) != null then
                $b + {control: $ctl, status: "PASS", actual: ($cat + " -> LAW " + ($e.workspaces | map(name_of) | join(", "))),
                      evidence: ($e.settingsSummary + (if ($seen | length) > 0 then " | ingestion observed in " + ($seen | join(", ")) else "" end))}
              elif $e.availableCategories != null and (($e.availableCategories | map(lc) | index($cat | lc)) == null) then
                $b + {control: $ctl, status: "NOT_APPLICABLE", reason: ($cat + " is not offered by this tenant (licensing/feature availability)")}
              else
                $b + {control: $ctl, status: "FAIL", severity: $sev, expected: ($cat + " exported to the central LAW"),
                      actual: ("Not exported to LAW. Entra settings: " + (if $e.settingsSummary == "" then "none" else $e.settingsSummary end)),
                      evidence: "GET /providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01",
                      recommendation: ("Enable " + $cat + " in Entra ID > Diagnostic settings towards the central LAW.")}
              end
            elif ($seen | length) > 0 then
              $b + {control: $ctl, status: "PASS", actual: ("Ingestion of " + $tbl + " observed (Usage table) in " + ($seen | join(", "))),
                    reason: ("Entra diagnostic settings not readable (" + $e.auditStatus + "); PASS based on LAW ingestion evidence only.")}
            else
              $b + {control: $ctl, status: "NOT_VERIFIABLE", severity: $sev,
                    reason: ("Entra diagnostic settings not readable (" + $e.auditStatus + ": " + ($e.auditError // "") + ") and no " + $tbl + " ingestion observed in audited workspaces (data queries: " + $cfg.dataQueries + ").")}
            end ),
        ( ["RiskyUsers","UserRiskEvents","RiskyServicePrincipals","ServicePrincipalRiskEvents"] as $risk
          | if $e.auditStatus == "OK" then
              ([$risk[] | select(. as $c | $e.availableCategories == null or (($e.availableCategories | map(lc) | index($c | lc)) != null))]) as $av
              | ([$av[] | select(. as $c | (($e.categoriesToLaw // []) | map(lc) | index($c | lc)) == null)]) as $miss
              | if ($av | length) == 0 then $b + {control: "ENTRA-007", status: "NOT_APPLICABLE", reason: "Risk log categories not offered (requires Entra ID P2)"}
                elif ($miss | length) == 0 then $b + {control: "ENTRA-007", status: "PASS", actual: ("Risk categories to LAW: " + ($av | join(", ")))}
                else $b + {control: "ENTRA-007", status: "WARNING", severity: "MEDIUM", actual: ("Risk categories not exported: " + ($miss | join(", ")))} end
            else
              ([ "AADRiskyUsers","AADUserRiskEvents" ] | map(active_in(.)) | add | unique) as $seen
              | if ($seen | length) > 0 then $b + {control: "ENTRA-007", status: "PASS", actual: ("Risk tables ingested in " + ($seen | join(", "))), reason: "Based on LAW ingestion evidence"}
                else $b + {control: "ENTRA-007", status: "NOT_VERIFIABLE", severity: "LOW", reason: ("Entra settings " + $e.auditStatus + "; risk logs depend on licensing (P2)")} end
            end ),
        ( if $e.auditStatus != "OK" then
            $b + {control: "ENTRA-008", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: ("Entra diagnostic settings not readable (" + $e.auditStatus + ")")}
          else archive_verdict($SM; $e.storageAccounts; ($e | diag_containers)) as $v
            | (($e.categoriesToEventHub | map(lc) | index("signinlogs")) != null or ((exported_via_law($e.workspaces; "SigninLogs") | map(select(.state == "EXPORTED")) | length) > 0)) as $stream
            | if $v.status == "PASS" and $stream then $b + {control: "ENTRA-008", status: "PASS", actual: ("WORM archive " + $v.text + "; streamed to Event Hub")}
              else $b + {control: "ENTRA-008", status: (if $v.status == "NOT_VERIFIABLE" then "NOT_VERIFIABLE" elif ($v.status == "PASS" or $stream) then "WARNING" else "FAIL" end), severity: "MEDIUM",
                         expected: "Entra logs archived to locked WORM storage and streamed to the SOC Event Hub",
                         actual: ("Archive: " + $v.text + "; Event Hub (direct or LAW export of SigninLogs): " + ($stream | tostring))} end
          end ) ),

    # ---- EH-001: security Event Hub exists ----
    ( ([$eh[] | select(.auditStatus == "OK" and ((.kind == "namespace" and .isSecurityStream) or (.kind == "eventhub" and (.name | rx($cfg.ehRegex)))))
           | (if .kind == "namespace" then .name else .namespaceName + "/" + .name end)] | unique) as $sec
      | ([$eh[] | select(.kind == "namespace" and .auditStatus != "OK")] | length) as $unread
      | {resourceId: "", resourceType: "microsoft.eventhub/namespaces", resourceName: "tenant scope", subscriptionId: ""} as $b
      | if ($sec | length) > 0 then $b + {control: "EH-001", status: "PASS", actual: ("Security Event Hub(s) matching " + $cfg.ehRegex + ": " + ($sec | join(", ")))}
        elif $unread > 0 then $b + {control: "EH-001", status: "NOT_VERIFIABLE", severity: "HIGH", reason: (($unread | tostring) + " Event Hub namespace(s) could not be read")}
        else $b + {control: "EH-001", status: "FAIL", severity: "HIGH", expected: ("Event Hub namespace or hub matching EXPECTED_EVENTHUB_REGEX=" + $cfg.ehRegex),
                   actual: "No matching Event Hub in the audited subscriptions",
                   reason: "Either the security Event Hub does not exist or it lives in a subscription outside the audit scope."} end ),

    # ---- EH-002 / EH-005 / EH-004: LAW -> Event Hub -> Cribl, per export destination ----
    ( $law[] | select(.auditStatus == "OK" and (.excluded | not) and .exportsStatus == "OK") | . as $L
      | {subscriptionId: $L.subscriptionId, resourceId: $L.id, resourceType: "microsoft.operationalinsights/workspaces", resourceName: $L.name, evidenceFile: $L.evidenceFile} as $b
      | if ($L.eventHubDestinations | length) == 0 then
          $b + {control: "EH-002", status: "FAIL", severity: "HIGH", expected: "LAW Data Export -> security Event Hub", actual: "No enabled Event Hub Data Export rule (see LAW-003)",
                reason: "AZURE_PIPELINE_CONFIGURED=false"}
        else
          ( $L.eventHubDestinations[] | . as $d | ($NS[$d.namespaceId] // null) as $n
            | ($b + {resourceName: ($L.name + " -> " + ($d.namespaceId | name_of) + "/" + ($d.eventHubName // "am-*") + " [" + $d.rule + "]")}) as $bd
            | ([$eh[] | select(.kind == "eventhub" and .namespaceId == $d.namespaceId)]) as $hubs
            | (if $d.eventHubName != null then [$hubs[] | select((.name | lc) == ($d.eventHubName | lc))]
               else [$hubs[] | select(. as $h | ($d.tables | map("am-" + lc) | index($h.name | lc)) != null)] end) as $tgt
            | ( if $n == null then $bd + {control: "EH-002", status: "NOT_VERIFIABLE", severity: "HIGH", reason: "Destination namespace was not audited"}
                elif $n.auditStatus == "NOTFOUND" then
                  $bd + {control: "EH-002", status: "FAIL", severity: "HIGH", actual: ("Destination namespace does not exist: " + $d.namespaceId), reason: "Export rule points to a deleted/nonexistent Event Hub namespace."}
                elif $n.auditStatus != "OK" and ($n.auditStatus | startswith("HUBS_") | not) then
                  $bd + {control: "EH-002", status: "NOT_VERIFIABLE", severity: "HIGH", reason: ("Destination namespace not readable: " + $n.auditStatus + " " + ($n.auditError // ""))}
                else
                  ([ (if $d.eventHubName != null and ($tgt | length) == 0 and ($n.auditStatus == "OK") then "FAIL:event hub '\''" + $d.eventHubName + "'\'' does not exist in namespace" else empty end),
                     (if (($n.publicNetworkAccess == "Disabled") or (($n.networkDefaultAction // "Allow") == "Deny")) and ($n.trustedServiceAccessEnabled | not) then
                        "FAIL:namespace firewall/private access without trusted Microsoft services bypass - Data Export cannot deliver" else empty end),
                     (if ($n.skuTier | lc) == "basic" then "WARN:Basic tier namespace (event size / feature limits)" else empty end),
                     (if (($n.name | rx($cfg.ehRegex)) or (($d.eventHubName // "") | rx($cfg.ehRegex))) | not then "WARN:destination does not match EXPECTED_EVENTHUB_REGEX (" + $cfg.ehRegex + ")" else empty end) ]) as $iss
                  | ("Rule " + $d.rule + ": " + ($d.tables | length | tostring) + " tables -> " + $n.name + "/" + ($d.eventHubName // "(per-table am-<table> hubs)")
                     + "; network " + $n.publicNetworkAccess + "/" + ($n.networkDefaultAction // "n/a") + ", trustedServices=" + ($n.trustedServiceAccessEnabled | tostring)) as $act
                  | if ($iss | map(select(startswith("FAIL:"))) | length) > 0 then
                      $bd + {control: "EH-002", status: "FAIL", severity: "HIGH", actual: $act, reason: ($iss | map(sub("^(FAIL|WARN):"; "")) | join("; "))}
                    elif ($iss | length) > 0 then
                      $bd + {control: "EH-002", status: "WARNING", severity: "MEDIUM", actual: $act, reason: ($iss | map(sub("^(FAIL|WARN):"; "")) | join("; "))}
                    else $bd + {control: "EH-002", status: "PASS", actual: $act, reason: "AZURE_PIPELINE_CONFIGURED"} end
                end ),
              ( if $n == null or $n.auditStatus != "OK" then empty
                else ($tgt | map(.incomingMessages) | map(select(. != null)) | add) as $in
                  | ($tgt | map(.outgoingMessages) | map(select(. != null)) | add) as $out
                  | ( if $n.metricsStatus != "OK" then $bd + {control: "EH-005", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: ("Namespace metrics not readable: " + $n.metricsStatus)}
                      elif ($tgt | length) == 0 then $bd + {control: "EH-005", status: "WARNING", severity: "HIGH",
                            actual: ("No target event hub found in namespace (" + ($d.eventHubName // "am-<table>") + ")"), reason: "No destination hub exists yet - Data Export has not delivered any table."}
                      elif ($in // 0) > 0 then $bd + {control: "EH-005", status: "PASS", actual: ("IncomingMessages last " + ($cfg.ehHours | tostring) + "h = " + ($in | tostring) + " on " + ($tgt | map(.name) | join(", "))), reason: "Azure-side delivery observed (not end-to-end)"}
                      else $bd + {control: "EH-005", status: "WARNING", severity: "HIGH", actual: ("IncomingMessages last " + ($cfg.ehHours | tostring) + "h = 0 on " + ($tgt | map(.name) | join(", "))),
                                  reason: "Export configured but no messages arrived in the lookback window."} end ),
                    ( ($tgt | map(.criblConsumerGroups // []) | add // []) as $cg
                      | ($cribl[0] // {configured: false}) as $C
                      | ([$C.inputs[]? | select(.disabled | not) | select((.brokers | tostring | lc | contains(($n.name | lc) + ".servicebus")) )]) as $ci
                      | ("Consumer groups matching " + $cfg.criblCgRegex + ": " + (if ($cg | length) > 0 then ($cg | unique | join(", ")) else "none" end)
                         + "; OutgoingMessages last " + ($cfg.ehHours | tostring) + "h = " + (($out // "n/a") | tostring)) as $ev
                      | if ($C.configured | not) then
                          if ($in // 0) > 0 and ($out != null) and ($out == 0) then
                            $bd + {control: "EH-004", status: "WARNING", severity: "HIGH", actual: "Messages arrive but nothing is consumed", evidence: $ev,
                                   reason: "No consumer (Cribl) read from the destination hub(s) in the lookback window."}
                          else
                            $bd + {control: "EH-004", status: "NOT_VERIFIABLE", severity: "MEDIUM", evidence: $ev,
                                   reason: "Azure-side Event Hub destination exists, but downstream Cribl ingestion cannot be verified from Azure alone (END_TO_END_DELIVERY_VERIFIED=false). Set CRIBL_API_URL/CRIBL_API_TOKEN for optional verification."}
                          end
                        elif $C.status != "OK" then $bd + {control: "EH-004", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: ("Cribl API " + $C.status + " (HTTP " + ($C.httpCode // "?") + ")"), evidence: $ev}
                        elif ($ci | length) == 0 then $bd + {control: "EH-004", status: "WARNING", severity: "HIGH", actual: ("No enabled Cribl Event Hub input references " + $n.name + ".servicebus.*"), evidence: $ev}
                        elif ($out // 0) > 0 then $bd + {control: "EH-004", status: "PASS", actual: ("Cribl input(s) " + ($ci | map(.id) | join(", ")) + " configured for namespace and hub is being consumed"),
                                                        evidence: $ev, reason: "CRIBL_INPUT_CONFIGURED + consumption observed; Elasticsearch/SOC delivery itself is not verified."}
                        else $bd + {control: "EH-004", status: "WARNING", severity: "MEDIUM", actual: ("Cribl input(s) " + ($ci | map(.id) | join(", ")) + " configured but no outgoing messages observed"), evidence: $ev} end )
                end ) )
        end ),

    # ---- ARC-001: archive storage configured anywhere ----
    ( ([$sto[] | select(.referenced)]) as $ref
      | {resourceId: "", resourceType: "microsoft.storage/storageaccounts", resourceName: "tenant scope", subscriptionId: ""} as $b
      | if ($ref | length) == 0 then $b + {control: "ARC-001", status: "FAIL", severity: "CRITICAL", expected: "At least one Storage archive destination for security logs",
                                          actual: "No Storage account is referenced by any diagnostic setting, Activity Log / Entra export, LAW Data Export or Event Hub Capture",
                                          reason: "No long-term (5-6 year) archive path exists in the audited scope."}
        else ($ref | map(select(.auditStatus == "OK" and .wormCompliant))) as $ok
          | $b + {control: "ARC-001", status: (if ($ok | length) > 0 then "PASS" else "WARNING" end), severity: "HIGH",
                  actual: ("Archive destinations: " + ($ref | map(.name + "=" + (.wormState // .auditStatus)) | join(", ")) + " | WORM-compliant: " + ($ok | length | tostring))} end ),

    # ---- APP-002: application telemetry reaches the Event Hub pipeline ----
    ( $appi[] | select(.workspaceBased) | . as $c
      | {subscriptionId: $c.subscriptionId, resourceId: $c.id, resourceType: "microsoft.insights/components", resourceName: $c.name} as $b
      | ($LM[$c.workspaceResourceId] // null) as $w
      | if $w == null then $b + {control: "APP-002", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: ("Workspace " + ($c.workspaceResourceId | name_of) + " is outside the audited scope")}
        elif $w.exportsStatus != "OK" then $b + {control: "APP-002", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: ("Workspace data exports not readable: " + $w.exportsStatus)}
        else (["AppRequests","AppEvents","AppExceptions","AppTraces","AppDependencies"] | map(select(. as $t | ($w.exportedToEventHub | map(lc) | index($t | lc)) != null))) as $ex
          | if ($ex | index("AppRequests")) != null then $b + {control: "APP-002", status: "PASS", actual: ("App tables exported from " + $w.name + ": " + ($ex | join(", ")))}
            else $b + {control: "APP-002", status: "FAIL", severity: "MEDIUM", expected: "AppRequests (and audit-relevant App* tables) exported to the security Event Hub",
                       actual: ("Workspace " + $w.name + " exports to Event Hub: " + (if ($w.exportedToEventHub | length) == 0 then "nothing" else ($w.exportedToEventHub | join(", ")) end))} end
        end ),

    # ---- DB-002 / DB-003 for PostgreSQL / MySQL flexible and SQL MI (diagnostic evidence) ----
    ( ($diag | map({key: (.id | lc), value: .}) | from_entries) as $D
      | $db[] | select(.engine == "PostgreSQLFlexible" or .engine == "MySQLFlexible" or .engine == "SQLManagedInstance") | . as $s
      | ({"PostgreSQLFlexible": "^PostgreSQLLogs$", "MySQLFlexible": "^MySqlAuditLogs$", "SQLManagedInstance": "^SQLSecurityAuditEvents$"}[$s.engine]) as $re
      | {subscriptionId: $s.subscriptionId, resourceId: $s.id, resourceType: ({"PostgreSQLFlexible": "microsoft.dbforpostgresql/flexibleservers", "MySQLFlexible": "microsoft.dbformysql/flexibleservers", "SQLManagedInstance": "microsoft.sql/managedinstances"}[$s.engine]), resourceName: $s.name} as $b
      | ($D[$s.id] // null) as $r
      | if $r == null or $r.auditStatus != "OK" then $b + {control: "DB-002", status: "NOT_VERIFIABLE", severity: "HIGH", reason: ("Diagnostic settings not available: " + (($r.auditStatus // "not audited") | tostring))}
        else ([$r.logCategories[] | select(test($re; "i"))]) as $cat
          | if ($cat | length) == 0 then $b + {control: "DB-002", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: ("Audit category (" + $re + ") not offered by this resource")}
            else
              ( if ([$r.categoriesToLaw[] | select(test($re; "i"))] | length) > 0 then
                  $b + {control: "DB-002", status: "PASS", actual: ($cat[0] + " -> LAW " + ($r.workspaces | map(name_of) | join(", ")))}
                else $b + {control: "DB-002", status: "FAIL", severity: "HIGH", expected: ($cat[0] + " sent to the central LAW"), actual: ("Settings: " + (if $r.settingsSummary == "" then "none" else $r.settingsSummary end)),
                           reason: "Database audit/server logs are not centrally collected."} end ),
              ( if ([$r.categoriesToStorage[] | select(test($re; "i"))] | length) > 0 then
                  archive_verdict($SM; $r.storageAccounts; ($r | diag_containers)) as $v
                  | $b + {control: "DB-003", status: $v.status, severity: ($v.severity // "MEDIUM"), actual: ($cat[0] + " archived to " + $v.text)}
                else $b + {control: "DB-003", status: "WARNING", severity: "MEDIUM", actual: ($cat[0] + " has no direct Storage archive destination")} end )
            end
        end ),

    # ---- DBX-002 / DBX-003 ----
    ( ($diag | map({key: (.id | lc), value: .}) | from_entries) as $D
      | $dbx[] | . as $w
      | {subscriptionId: $w.subscriptionId, resourceId: $w.id, resourceType: "microsoft.databricks/workspaces", resourceName: $w.name} as $b
      | ($D[$w.id] // null) as $r
      | if $r == null or $r.auditStatus != "OK" then $b + {control: "DBX-002", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: ("Diagnostic settings not available: " + (($r.auditStatus // "not audited") | tostring))}
        else
          ( if ([$r.logCategories[] | select(lc == "unitycatalog")] | length) == 0 then
              $b + {control: "DBX-002", status: "NOT_VERIFIABLE", severity: "MEDIUM", reason: ("Category unityCatalog not offered by this workspace (available: " + ($r.logCategories | join(", ")) + ")")}
            elif ([$r.categoriesToLaw[] | select(lc == "unitycatalog")] | length) > 0 then
              $b + {control: "DBX-002", status: "PASS", actual: "unityCatalog -> LAW", reason: "Category-level evidence only; event completeness (data access events) requires Databricks-side verification."}
            else $b + {control: "DBX-002", status: "FAIL", severity: "MEDIUM", expected: "unityCatalog category sent to LAW", actual: ("Settings: " + (if $r.settingsSummary == "" then "none" else $r.settingsSummary end))} end ),
          ( ([$r.logCategories[] | select(lc | IN("accounts", "workspace", "iamrole", "secrets", "sqlpermissions", "clusters", "jobs", "notebook", "dbfs", "databrickssql", "filesystem"))]) as $want
            | ([$want[] | select(. as $c | ($r.categoriesToLaw | map(lc) | index($c | lc)) == null)]) as $miss
            | if ($want | length) == 0 then empty
              elif ($miss | length) == 0 then $b + {control: "DBX-003", status: "PASS", actual: ("To LAW: " + ($want | join(", ")))}
              else $b + {control: "DBX-003", status: "FAIL", severity: "MEDIUM", expected: ("Access/workspace activity categories to LAW: " + ($want | join(", "))), actual: ("Missing: " + ($miss | join(", ")))} end )
        end ),

    # ---- UWWB-001 / UWWB-002: application CRUD audit evidence ----
    ( ([$lt[] | select(.table | rx($cfg.uwwbRegex))]) as $tabs
      | ([$inv[] | select((.type == "microsoft.insights/datacollectionrules" or .type == "microsoft.insights/datacollectionendpoints")
                          and ((.name | rx($cfg.uwwbRegex)) or ((.properties.streamDeclarations // {}) | keys | map(select(rx($cfg.uwwbRegex))) | length > 0)
                               or ([(.properties.dataFlows // [])[] | .outputStream // empty] | map(select(rx($cfg.uwwbRegex))) | length > 0)))]) as $dcr
      | ([$appi[] | select(.name | rx($cfg.uwwbRegex))]) as $ai
      | {resourceId: "", resourceType: "application", resourceName: "UWWB application audit logging", subscriptionId: ""} as $b
      | ("Tables: " + (if ($tabs | length) == 0 then "none" else ($tabs | map(.workspaceName + "/" + .table + (if .active == true then "(active)" elif .active == false then "(no data)" else "" end)) | join(", ")) end)
         + " | DCR/DCE: " + (if ($dcr | length) == 0 then "none" else ($dcr | map(.name) | join(", ")) end)
         + " | App Insights: " + (if ($ai | length) == 0 then "none" else ($ai | map(.name) | join(", ")) end)) as $ev
      | ($b + {control: "UWWB-001", status: "NOT_VERIFIABLE", severity: (if ($tabs | length) + ($dcr | length) + ($ai | length) == 0 then "MEDIUM" else "LOW" end),
               evidence: $ev, actual: (if ($tabs | length) + ($dcr | length) + ($ai | length) == 0 then ("No Azure-side artifact matching UWWB_REGEX=" + $cfg.uwwbRegex) else "Candidate artifacts found (see evidence)" end),
               reason: "NOT_VERIFIABLE_FROM_AZURE_CONTROL_PLANE: CREATE/UPDATE/DELETE audit semantics, completeness and payload hygiene are application behaviour; table names alone do not prove compliance.",
               recommendation: "Verify with application owners: sample events per operation type, field schema, and absence of payload/PII."}),
        ( $tabs[] | select((.customColumns | length) > 0) | . as $t
          | ([$t.customColumns[] | select(rx($cfg.payloadRegex))]) as $pc
          | if ($pc | length) > 0 then
              $b + {control: "UWWB-002", status: "WARNING", severity: "MEDIUM", resourceName: ($t.workspaceName + "/" + $t.table), resourceId: ($t.workspaceId + "/tables/" + $t.table),
                    actual: ("Columns suggesting payload logging: " + ($pc | join(", "))), evidence: ("Schema columns: " + ($t.customColumns | join(", "))),
                    reason: "Schema-only heuristic; logs should be metadata-focused."}
            else $b + {control: "UWWB-002", status: "PASS", resourceName: ($t.workspaceName + "/" + $t.table), resourceId: ($t.workspaceId + "/tables/" + $t.table),
                       actual: ("No payload-like columns in schema: " + ($t.customColumns | join(", ")))} end ) )
  ' -c -n "${common[@]}" > "$f" 2>"$f.err"
  if [ -s "$f.err" ]; then log_error "internal: correlation failed: $(head -c 500 "$f.err")"; record_error correlation jq "" ERROR "$(head -c 500 "$f.err")"; fi
  ingest_findings "$f"
  rm -f "$f" "$f.err"
}

build_corr_cfg() {
  CORR_CFG="$(jq -nc --argjson archiveMin "$ARCHIVE_RETENTION_MIN_DAYS" --arg ehRegex "$EXPECTED_EVENTHUB_REGEX" \
     --arg criblCgRegex "$CRIBL_CONSUMER_GROUP_REGEX" --argjson ehHours "$EH_METRICS_LOOKBACK_HOURS" \
     --arg uwwbRegex "$UWWB_REGEX" --arg payloadRegex "$UWWB_PAYLOAD_COLUMN_REGEX" --arg dataQueries "$ENABLE_DATA_QUERIES" \
     '{archiveMin: $archiveMin, ehRegex: $ehRegex, criblCgRegex: $criblCgRegex, ehHours: $ehHours, uwwbRegex: $uwwbRegex,
       payloadRegex: $payloadRegex, dataQueries: $dataQueries}')"
}

# =============================================================================
# SUBSCRIPTION ORCHESTRATION
# =============================================================================
audit_subscription() { # <index> <total> <sub> <subname>
  local idx="$1" total="$2" sub="$3" subname="$4" rc cnt
  log_info ""
  log_info "[$idx/$total] Auditing subscription: $subname ($sub)"
  inventory_resources "$sub" "$subname"; rc=$?
  if [ $rc -ne 0 ]; then
    log_error "Subscription $subname could not be inventoried ($(rc_name $rc)) - skipping"
    add_finding control=SUB-001 status="$(rc_status $rc)" severity=HIGH subscriptionId="$sub" resourceId="/subscriptions/$sub" \
      resourceName="$subname" resourceType=microsoft.resources/subscriptions \
      actual="Subscription not auditable" reason="Resource inventory failed ($(rc_name $rc)); subscription may have been disabled/removed or access is missing."
    return
  fi
  audit_subscription_activity_logs "$sub" "$subname"
  audit_diagnostic_settings "$sub" "$subname"
  audit_log_analytics "$sub" "$subname"
  audit_event_hubs "$sub" "$subname"
  audit_application_insights "$sub" "$subname"
  audit_postgresql "$sub" "$subname"
  audit_mysql "$sub" "$subname"
  audit_sql "$sub" "$subname"
  audit_databricks "$sub" "$subname"
  add_finding control=SUB-001 status=PASS subscriptionId="$sub" resourceId="/subscriptions/$sub" resourceName="$subname" \
    resourceType=microsoft.resources/subscriptions actual="Subscription inventoried and audited"
  cnt="$(find "$WORK/shards" -name findings.jsonl -exec cat {} + 2>/dev/null | grep -F "\"subscriptionId\":\"$sub\"" | grep -cE '"status":"(FAIL|WARNING)"')"
  log_info "Subscription completed with ${cnt:-0} FAIL/WARNING findings"
}

# =============================================================================
# REPORTS
# =============================================================================
write_csv() { # <out> <jsonl in> <comma-separated columns> [jq pre-transform]
  local out="$1" in="$2" cols="$3" pre="${4:-.}"
  {
    jq -rn --arg c "$cols" '($c | split(",")) | @csv + "\r"'
    if [ -s "$in" ]; then
      jqlib "($pre) as \$o | (\$c | split(\",\")) | map(. as \$k | \$o[\$k]) | csvrow + \"\\r\"" -r --arg c "$cols" "$in"
    fi
  } > "$out"
}

generate_csv() {
  local d="$RUN_DIR" diag inv
  diag="$(merged diagnostic)"; inv="$(merged resources)"
  write_csv "$d/findings.csv" "$(merged findings)" \
    "control,title,status,severity,subscriptionId,subscriptionName,resourceGroup,resourceType,resourceName,resourceId,expected,actual,evidence,reason,recommendation,regulatory,evidenceFile,timestamp"
  # resources.csv = inventory joined with diagnostic coverage
  jq -c --slurpfile d "$diag" '($d | map({key: (.id | ascii_downcase), value: .}) | from_entries) as $D
      | ($D[(.id | ascii_downcase)] // {}) as $x
      | . + {diagAuditStatus: ($x.auditStatus // "NOT_AUDITED"), diagSupported: ($x.supported // null),
             logCategoryCount: (($x.logCategories // []) | length), settingsCount: ($x.settingsCount // null), coverage: ($x.coverage // null)}' "$inv" > "$WORK/resources_joined.jsonl"
  write_csv "$d/resources.csv" "$WORK/resources_joined.jsonl" \
    "subscriptionId,subscriptionName,resourceGroup,type,kind,location,name,skuName,id,diagAuditStatus,diagSupported,logCategoryCount,settingsCount,coverage"
  write_csv "$d/diagnostic-settings.csv" "$diag" \
    "subscriptionId,subscriptionName,resourceGroup,type,name,id,auditStatus,auditError,supported,coverage,isProd,isCritical,logCategories,categoryGroupsAvailable,settingsCount,settingsSummary,enabledCategories,missingCategories,requiredBasis,requiredCategories,missingRequired,requiredNotToLaw,requiredNotToStorage,requiredNotToEventHub,workspaces,storageAccounts,eventHubNamespaces,eventHubNames,metricsEnabled,allLogsEnabled,azureDiagnosticsMode,dedicatedMode,legacyRetentionDays"
  jq -c --slurpfile a "$(merged appinsights)" '. as $l | . + {linkedAppInsights: [$a[] | select(.workspaceResourceId == $l.id) | .name]}' "$(merged law)" > "$WORK/law_joined.jsonl"
  write_csv "$d/law.csv" "$WORK/law_joined.jsonl" \
    "subscriptionId,subscriptionName,resourceGroup,name,id,location,sku,customerId,retentionInDays,dailyQuotaGb,publicNetworkAccessForIngestion,publicNetworkAccessForQuery,disableLocalAuth,auditStatus,auditError,tablesStatus,usageStatus,exportsStatus,lawTablesCount,activeTablesCount,exportRulesCount,enabledEventHubRules,exportedToEventHub,exportedToStorage,missingExports,missingExportsUnconfirmed,unsupportedActive,exportedNonexistent,azureDiagnosticsActive,customLogTables,activeAppTables,linkedAppInsights"
  write_csv "$d/law-tables.csv" "$(merged law_tables)" \
    "workspaceName,workspaceId,subscriptionId,table,plan,tableType,tableSubType,class,retentionInDays,retentionInherited,totalRetentionInDays,totalRetentionInherited,archiveRetentionInDays,active,lastSeen,volumeMB,exportEligibility,eligibilityReason,exportedToEventHub,exportedToStorage,exportRules"
  write_csv "$d/law-data-exports.csv" "$(merged law_exports)" \
    "workspaceName,workspaceId,subscriptionId,rule,enabled,destinationType,destinationId,eventHubName,tableCount,tables,createdDate,lastModifiedDate"
  write_csv "$d/event-hubs.csv" "$(merged eventhubs)" \
    "kind,subscriptionId,subscriptionName,resourceGroup,namespaceName,name,id,auditStatus,auditError,outOfScope,isSecurityStream,skuName,skuTier,capacity,autoInflate,maxThroughputUnits,publicNetworkAccess,networkDefaultAction,trustedServiceAccessEnabled,ipRules,vnetRules,approvedPrivateEndpoints,minimumTlsVersion,disableLocalAuth,authorizationRules,partitionCount,retentionHours,consumerGroups,criblConsumerGroups,captureEnabled,captureDestination,captureStorageAccountId,captureContainer,incomingMessages,outgoingMessages,metricsStatus" \
    '. + {authorizationRules: ((.authorizationRules // []) | map(.name + ":" + ((.rights // []) | join("/")))), namespaceName: (.namespaceName // .name)}'
  write_csv "$d/storage.csv" "$(merged storage)" \
    "subscriptionId,subscriptionName,resourceGroup,name,id,location,kind,sku,auditStatus,auditError,referenced,reasons,isHnsEnabled,minimumTlsVersion,supportsHttpsTrafficOnly,publicNetworkAccess,networkDefaultAction,allowBlobPublicAccess,allowSharedKeyAccess,blobVersioning,blobSoftDelete,blobSoftDeleteDays,containerSoftDelete,containerSoftDeleteDays,changeFeed,changeFeedRetentionDays,lifecycleRules,lifecycleMinDeleteDays,accountVersionLevelImmutability,accountImmutabilityPolicyState,accountImmutabilityPeriodDays,containersTotal,containersEvaluated,evaluationBasis,wormState,wormCompliant,minImmutabilityDays,meetsTarget,containerStates"
  write_csv "$d/worm-policies.csv" "$(merged worm)" \
    "subscriptionId,subscriptionName,storageAccountName,storageAccountId,container,isLogContainer,evaluated,hasImmutabilityPolicy,policyScope,policyState,immutabilityPeriodDays,allowProtectedAppendWrites,allowProtectedAppendWritesAll,legalHold,legalHoldTags,versionLevelImmutability,wormState,wormCompliant,meetsTarget,lastModifiedTime"
  write_csv "$d/rbac.csv" "$(merged rbac)" \
    "scopeType,scopeName,scope,subscriptionId,assignmentType,inheritance,assignmentScope,principalType,principalId,principalDisplayName,principalNameStatus,roleName,roleType,roleClass,privileged,allowlisted,expectedReaderGroup,hasCondition,memberType,assignmentId"
  write_csv "$d/activity-log.csv" "$(merged activity)" \
    "subscriptionId,subscriptionName,auditStatus,auditError,settingsCount,settingsSummary,availableCategories,enabledCategories,categoriesToLaw,categoriesToStorage,categoriesToEventHub,requiredNotToLaw,requiredNotToStorage,requiredNotToEventHub,expectedMissing,workspaces,storageAccounts,eventHubNamespaces,eventHubNames"
  write_csv "$d/application-insights.csv" "$(merged appinsights)" \
    "subscriptionId,subscriptionName,resourceGroup,name,id,location,applicationType,workspaceBased,workspaceResourceId,ingestionMode,retentionInDays,disableLocalAuth,publicNetworkAccessForIngestion,publicNetworkAccessForQuery"
  write_csv "$d/databases.csv" "$(merged databases)" \
    "engine,subscriptionId,subscriptionName,resourceGroup,name,id,location,auditStatus,auditError,auditState,isAzureMonitorTargetEnabled,auditToLaw,auditToEventHub,auditToStorageViaDiag,storageAccountName,retentionDays,auditActionsAndGroups,devOpsAuditState,masterSettingsSummary,databaseAudits,pgauditLoaded,sharedPreloadLibraries,pgauditLog,pgauditEffectiveClasses,pgauditMissingClasses,pgauditLogParameter,logConnections,logDisconnections,logStatement,auditLogEnabled,auditLogEvents" \
    '. + {databaseAudits: ((.databaseAudits // []) | map((.id | split("/") | last) + "=" + .state))}'
  jq -c --slurpfile d "$diag" '. as $w | ([$d[] | select((.id | ascii_downcase) == $w.id)] | first) as $x
      | . + {diagAuditStatus: ($x.auditStatus // "NOT_AUDITED"), logCategories: ($x.logCategories // []), enabledCategories: ($x.enabledCategories // []),
             categoriesToLaw: ($x.categoriesToLaw // []), missingCategories: ($x.missingCategories // []), settingsSummary: ($x.settingsSummary // "")}' \
     "$(merged databricks)" > "$WORK/dbx_joined.jsonl"
  write_csv "$d/databricks.csv" "$WORK/dbx_joined.jsonl" \
    "subscriptionId,subscriptionName,resourceGroup,name,id,location,sku,workspaceUrl,publicNetworkAccess,enableNoPublicIp,diagAuditStatus,logCategories,enabledCategories,categoriesToLaw,missingCategories,settingsSummary"
  write_csv "$d/errors.csv" "$(merged errors)" "timestamp,area,operation,subscriptionId,resourceId,code,message"
}

write_report_lib() {
  cat >> "$JQLIB_DIR/lib.jq" <<'JQEOF'

def domain_of:
  if test("^LOG-00[5]$") then "WORM Archive"
  elif startswith("LOG-") then "Resource Diagnostics"
  elif test("^LAW-00[12]$") then "LAW Retention"
  elif test("^LAW-00[345]$") or IN("EH-001", "EH-002", "EH-005") then "LAW -> Event Hub"
  elif startswith("LAW-") then "LAW Governance"
  elif . == "EH-004" then "Event Hub -> Cribl"
  elif startswith("EH-") then "Event Hub Security"
  elif startswith("ARC-") then "WORM Archive"
  elif startswith("ACT-") then "Activity Logs"
  elif startswith("DB-") then "Database Audit"
  elif startswith("ENTRA-") then "Entra Logging"
  elif startswith("DBX-") then "Databricks"
  elif startswith("APP-") then "Application Insights"
  elif startswith("LOGCAT-") then "Log Categorization"
  elif startswith("UWWB-") then "UWWB App Audit"
  elif startswith("RBAC-") then "RBAC"
  else "Audit Coverage" end;
def domains: ["Resource Diagnostics", "LAW Retention", "LAW -> Event Hub", "Event Hub -> Cribl", "Event Hub Security", "WORM Archive",
              "Activity Logs", "Database Audit", "Entra Logging", "Databricks", "Application Insights", "RBAC", "LAW Governance",
              "Log Categorization", "UWWB App Audit", "Audit Coverage"];
def counts: {pass: (map(select(.status == "PASS")) | length), fail: (map(select(.status == "FAIL")) | length),
             warning: (map(select(.status == "WARNING")) | length), notApplicable: (map(select(.status == "NOT_APPLICABLE")) | length),
             notVerifiable: (map(select(.status == "NOT_VERIFIABLE")) | length), errors: (map(select(.status == "ERROR")) | length)};
def md: s | gsub("\\|"; "\\|") | gsub("[\r\n]+"; " ");
def trunc($n): if (. | length) > $n then .[0:$n] + "..." else . end;
def pad($label; $n): $label + " " + (if ($n - ($label | length)) > 0 then ("-" * ($n - ($label | length))) else "" end);
def sevrank: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[.] // 5;
def strank: {"FAIL": 0, "ERROR": 1, "WARNING": 2, "NOT_VERIFIABLE": 3, "PASS": 4, "NOT_APPLICABLE": 5}[.] // 6;
JQEOF
}

generate_json() {
  local f="$RUN_DIR/summary.json"
  jqlib '
    ($findings) as $F | ($subs0[0] // []) as $subs
    | {
        audit: {
          tool: $tool, toolVersion: $ver, timestamp: $ts, completedAt: $completed, durationSeconds: $dur, interrupted: ($interrupted == "true"),
          tenantId: $tenant, subscriptions: ($subs | map(select(.include)) | length),
          subscriptionList: ($subs | map({id, name, state, included: .include, skipReason, isManagement})),
          azureCli: $azv[0], bash: $bash, jq: $jqv, identityType: ($acct[0].identityType // "unknown"),
          readOnly: true, outputDirectory: $dir,
          configuration: $conf[0]
        },
        summary: (($F | counts) + {bySeverity: {}, technicalErrors: ($errors | length)}),
        metrics: $metrics[0],
        architecture: (domains | map(. as $d | ([$F[] | select(.control | domain_of == $d)]) as $x
                       | {key: $d, value: {status: (if ($x | length) == 0 then "NOT_VERIFIABLE" else ($x | worst_status) end), counts: ($x | counts), evidence: (if ($x | length) == 0 then "no evidence collected" else "" end)}}) | from_entries),
        limitations: $lim[0],
        disclaimer: "Results are technical control evidence supporting compliance assessments (e.g. DORA Art. 12, ISO/IEC 27001:2022 A.5.28/A.8.15). They do not by themselves establish regulatory compliance.",
        findings: $F
      }
    | .summary.bySeverity = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as $sv | reduce $sv[] as $x ({}; .[$x] = ([$F[] | select(.severity == $x and (.status == "FAIL" or .status == "WARNING"))] | length)))' \
    -n --slurpfile findings "$(merged findings)" \
    --arg tool "$TOOL_NAME" --arg ver "$TOOL_VERSION" --arg ts "$RUN_TS" --arg completed "$(now_iso)" --argjson dur "$(( $(date +%s) - START_EPOCH ))" \
    --arg interrupted "$INTERRUPTED" --arg tenant "$TENANT_ID" --slurpfile subs0 "$WORK/subscriptions.json" \
    --slurpfile azv "$WORK/azversion.json" --arg bash "$BASH_VERSION" --arg jqv "$(jq --version)" --slurpfile acct "$WORK/account.json" \
    --arg dir "$RUN_DIR" --slurpfile conf "$WORK/config.json" --slurpfile metrics "$WORK/metrics.json" \
    --slurpfile errors "$(merged errors)" --slurpfile lim "$WORK/limitations.json" > "$f" 2>"$WORK/summary.err" \
    || log_error "summary.json generation failed: $(head -c 300 "$WORK/summary.err")"
}

compute_metrics() {
  jq -n --slurpfile d "$(merged diagnostic)" --slurpfile r "$(merged resources)" '
    ($d | map(select(.type | test("^microsoft\\.storage/storageaccounts/(blob|file|queue|table)services$") | not))) as $top
    | {
        totalResourcesDiscovered: ($r | length),
        diagnosticScopesEvaluated: ($d | length),
        storageServiceScopes: (($d | length) - ($top | length)),
        resourcesSupportingDiagnosticSettings: ([$d[] | select(.supported == true and .auditStatus == "OK")] | length),
        resourcesRequiringDiagnostics: ([$d[] | select(.auditStatus == "OK" and ((.logCategories // []) | length) > 0)] | length),
        resourcesWithDiagnosticSettings: ([$d[] | select(.auditStatus == "OK" and ((.logCategories // []) | length) > 0 and .settingsCount > 0)] | length),
        resourcesWithoutDiagnosticSettings: ([$d[] | select(.auditStatus == "OK" and ((.logCategories // []) | length) > 0 and .settingsCount == 0)] | length),
        resourcesPartiallyConfigured: ([$d[] | select(.coverage == "PARTIAL" or .coverage == "METRICS_ONLY")] | length),
        resourcesFullyConfigured: ([$d[] | select(.coverage == "FULL")] | length),
        resourcesMetricsOnlyType: ([$d[] | select(.coverage == "METRICS_ONLY_RESOURCE")] | length),
        resourcesNotSupportingDiagnostics: ([$d[] | select(.coverage == "NOT_SUPPORTED")] | length),
        resourcesSkippedByConfig: ([$d[] | select(.coverage == "SKIPPED_BY_CONFIG")] | length),
        resourcesUnableToAudit: ([$d[] | select(.auditStatus != "OK" and .auditStatus != "UNSUPPORTED" and .auditStatus != "SKIPPED")] | length),
        resourcesUnableToAuditForbidden: ([$d[] | select(.auditStatus == "FORBIDDEN" or .auditStatus == "AUTH")] | length)
      }' > "$WORK/metrics.json"
}

compute_limitations() {
  jq -n --slurpfile e "$(merged errors)" --slurpfile en "$(merged entra)" --slurpfile l "$(merged law)" \
        --slurpfile subs "$WORK/subscriptions.json" --slurpfile cr "$WORK/cribl.json" --slurpfile m "$WORK/metrics.json" \
        --arg rbac "$OPT_SKIP_RBAC" --arg tables "$OPT_SKIP_TABLES" --arg dq "$ENABLE_DATA_QUERIES" --arg sup "$EXPORT_SUPPORTED_TABLES_FILE" \
        --arg interrupted "$INTERRUPTED" --arg parallel "$MAX_PARALLEL" '
    ($e | group_by(.code) | map({code: .[0].code, n: length})) as $byCode
    | [
        (if $interrupted == "true" then "AUDIT INTERRUPTED - results are partial and must not be used as complete evidence." else empty end),
        ($byCode[] | select(.code == "FORBIDDEN") | "\(.n) Azure API request(s) returned HTTP 403 / insufficient permissions (see errors.csv) - affected controls are NOT_VERIFIABLE, not FAIL"),
        ($byCode[] | select(.code == "AUTH") | "\(.n) request(s) failed with authentication / conditional-access errors"),
        ($byCode[] | select(.code == "NOTFOUND") | "\(.n) request(s) returned 404 (resources deleted/moved during the audit or feature not configured)"),
        ($byCode[] | select(.code != "FORBIDDEN" and .code != "AUTH" and .code != "NOTFOUND") | "\(.n) request(s) failed technically with code \(.code)"),
        ([$e[] | select(.message | test("INCOMPLETE_PAGINATION"))] | length | select(. > 0) | "\(.) list operation(s) had incomplete pagination; affected inventories are incomplete"),
        (if $m[0].resourcesUnableToAudit > 0 then "\($m[0].resourcesUnableToAudit) resource scope(s) could not be audited for diagnostic settings" else empty end),
        (($en[0] // {auditStatus: "SKIPPED"}) | if .auditStatus != "OK" then "Entra ID diagnostic settings unavailable to current identity (" + .auditStatus + "); Entra controls rely on LAW ingestion evidence where available" else empty end),
        ([$l[] | select(.auditStatus == "OK" and .usageStatus != "OK" and .usageStatus != "SKIPPED")] | length | select(. > 0) | "\(.) workspace(s) did not allow the Usage metadata query (no Log Analytics data read access); table activity and export coverage are NOT_VERIFIABLE there"),
        (if $dq != "true" then "LAW data queries disabled: active tables, AzureDiagnostics usage and ingestion-based Entra evidence not evaluated" else empty end),
        (if $tables == "true" then "LAW table analysis skipped (--skip-table-analysis): table retention and export coverage not evaluated" else empty end),
        (if $rbac == "true" then "RBAC audit skipped (--skip-rbac)" else empty end),
        (if $sup == "" then "LAW Data Export eligibility is heuristic: Microsoft does not expose the supported-table list via API (set EXPORT_SUPPORTED_TABLES_FILE)" else empty end),
        (($cr[0] // {}) | if (.configured // false) | not then "Cribl downstream ingestion not accessible (no CRIBL_API_URL/CRIBL_API_TOKEN); Event Hub -> Cribl -> Elasticsearch/SOC delivery is NOT_VERIFIABLE" else "Cribl API queried for input configuration only; Elasticsearch/SOC indexing is not verified" end),
        "Databricks Unity Catalog system tables, verbose audit logs and lineage are Databricks data-plane configuration and were not inspected",
        "UWWB application CRUD audit semantics cannot be proven from the Azure control plane (NOT_VERIFIABLE_FROM_AZURE_CONTROL_PLANE)",
        "Blob-level (version-level) immutability policies on individual blobs and per-database pgaudit extension state are data-plane settings not visible via ARM",
        "RBAC shows configured assignments (incl. inherited and PIM-eligible); effective permissions (deny assignments, nested groups, conditions) are not computed; user display names are intentionally not resolved",
        "Table activity is derived from the LAW Usage table over the lookback window; tables that are free/non-billable and absent from Usage may appear inactive",
        "Azure Resource Graph inventory can lag behind ARM by several minutes",
        ($subs[0] | map(select(.include | not)) | group_by(.skipReason)[] | "\(length) subscription(s) not audited: \(.[0].skipReason)")
      ]' > "$WORK/limitations.json"
}

write_config_snapshot() {
  jq -n --arg a "$HOT_RETENTION_MIN_DAYS" --arg b "$HOT_RETENTION_MAX_DAYS" --arg c "$DEBUG_RETENTION_MAX_DAYS" \
        --arg d "$ARCHIVE_RETENTION_MIN_DAYS" --arg e "$ARCHIVE_RETENTION_TARGET_DAYS" --arg f "$EXPECTED_EVENTHUB_REGEX" \
        --arg g "$REQUIRED_CATEGORIES_MODE" --arg h "$REQUIRED_CATEGORY_REGEX" --arg i "$RESOURCE_ARCHIVE_POLICY" \
        --arg j "$CENTRAL_LAW_REGEX" --arg k "$PROD_REGEX" --arg l "$DEBUG_TABLE_REGEX" --arg m "$ARCHIVE_STORAGE_REGEX" \
        --arg n "$LOG_CONTAINER_REGEX" --arg o "$EXPECTED_READER_GROUPS_REGEX" --arg p "$EXCLUDE_SUBSCRIPTIONS_REGEX" \
        --arg q "$MAX_PARALLEL" --arg r "$MAX_RETRIES" --arg s "$ACTIVE_TABLE_LOOKBACK_DAYS" --arg t "$EXPORT_SUPPORTED_TABLES_FILE" \
        --arg u "$([ -n "$CRIBL_API_URL" ] && echo configured || echo 'not configured')" \
    '{HOT_RETENTION_MIN_DAYS: $a, HOT_RETENTION_MAX_DAYS: $b, DEBUG_RETENTION_MAX_DAYS: $c, ARCHIVE_RETENTION_MIN_DAYS: $d,
      ARCHIVE_RETENTION_TARGET_DAYS: $e, EXPECTED_EVENTHUB_REGEX: $f, REQUIRED_CATEGORIES_MODE: $g, REQUIRED_CATEGORY_REGEX: $h,
      RESOURCE_ARCHIVE_POLICY: $i, CENTRAL_LAW_REGEX: $j, PROD_REGEX: $k, DEBUG_TABLE_REGEX: $l, ARCHIVE_STORAGE_REGEX: $m,
      LOG_CONTAINER_REGEX: $n, EXPECTED_READER_GROUPS_REGEX: $o, EXCLUDE_SUBSCRIPTIONS_REGEX: $p, MAX_PARALLEL: $q, MAX_RETRIES: $r,
      ACTIVE_TABLE_LOOKBACK_DAYS: $s, EXPORT_SUPPORTED_TABLES_FILE: $t, CRIBL_API: $u}' > "$WORK/config.json"
}

generate_markdown() {
  local f="$RUN_DIR/summary.md"
  jq -c '{id, name, type, isCritical, auditStatus, coverage, logCategories, storageAccounts, categoriesToEventHub, workspaces}' "$(merged diagnostic)" > "$WORK/diag_projection.jsonl"
  jqlib '
    $sum[0] as $S | $S.findings as $F | $S.metrics as $M
    | ($law | map({key: .id, value: .}) | from_entries) as $LM
    | ([$law[] | select(.auditStatus == "OK" and ((.name | rx($centralRe)) or $centralRe == ""))][0].id // "<CENTRAL_LAW_RESOURCE_ID>") as $centralLaw
    | ([$sto[] | select(.auditStatus == "OK" and .wormCompliant)][0].id // "<IMMUTABLE_ARCHIVE_STORAGE_ACCOUNT_ID>") as $archive
    | ([$eh[] | select(.kind == "namespace" and .isSecurityStream)][0].id // "<SECURITY_EVENTHUB_NAMESPACE_ID>") as $secNs
    | def frow: "| " + ([.control, .status, .severity, (.resourceName | trunc(60)), (.subscriptionName | trunc(30)), (.actual | trunc(220)), (.expected | trunc(120))] | map(md) | join(" | ")) + " |";
      def fhdr: "| Control | Status | Severity | Resource | Subscription | Observed | Expected |", "|---|---|---|---|---|---|---|";
      def st($c; $rid): ([$F[] | select(.control == $c and (.resourceId | lc) == ($rid | lc))] | if length == 0 then "N/A" else worst_status end);
    "# Azure Audit Logging Compliance Review",
    "",
    "_Generated by \($S.audit.tool) \($S.audit.toolVersion) on \($S.audit.completedAt) - tenant `\($S.audit.tenantId)` - read-only audit_",
    "",
    "> Results are **technical control evidence supporting compliance** (DORA Art. 12 logging requirements, ISO/IEC 27001:2022 A.5.28 / A.8.15).",
    "> They do not by themselves establish that the organization is compliant with any regulation.",
    (if $S.audit.interrupted then "", "> **WARNING: the audit was interrupted. Results are partial.**" else empty end),
    "",
    "## Executive Summary",
    "",
    "```text",
    "Subscriptions in scope             : \($S.audit.subscriptions)",
    "Subscriptions fully inventoried    : \([$F[] | select(.control == "SUB-001" and .status == "PASS")] | length)",
    "Resources discovered               : \($M.totalResourcesDiscovered)",
    "Diagnostic scopes evaluated        : \($M.diagnosticScopesEvaluated) (incl. \($M.storageServiceScopes) storage service scopes)",
    "Resources supporting diag settings : \($M.resourcesSupportingDiagnosticSettings)",
    "Resources requiring diagnostics    : \($M.resourcesRequiringDiagnostics)",
    "  with diagnostic settings         : \($M.resourcesWithDiagnosticSettings)",
    "  without diagnostic settings      : \($M.resourcesWithoutDiagnosticSettings)",
    "  partially configured             : \($M.resourcesPartiallyConfigured)",
    "  fully configured                 : \($M.resourcesFullyConfigured)",
    "Resources unable to audit          : \($M.resourcesUnableToAudit) (403: \($M.resourcesUnableToAuditForbidden))",
    "",
    "PASS           : \($S.summary.pass)",
    "FAIL           : \($S.summary.fail)",
    "WARNING        : \($S.summary.warning)",
    "NOT VERIFIABLE : \($S.summary.notVerifiable)",
    "NOT APPLICABLE : \($S.summary.notApplicable)",
    "ERROR          : \($S.summary.errors)",
    "",
    "FAIL/WARNING by severity: CRITICAL=\($S.summary.bySeverity.CRITICAL) HIGH=\($S.summary.bySeverity.HIGH) MEDIUM=\($S.summary.bySeverity.MEDIUM) LOW=\($S.summary.bySeverity.LOW)",
    "Technical errors (errors.csv): \($S.summary.technicalErrors)",
    "```",
    "",
    (if ($S.summary.notVerifiable + $S.summary.errors) > 0 or ($S.limitations | length) > 0 then
       "> Parts of the environment could not be fully examined - see **Audit Coverage Limitations**. This report does not imply complete compliance for those parts." else empty end),
    "",
    "## Architecture Assessment",
    "",
    "```text",
    ($S.architecture | to_entries[] | select(.value.counts | (.pass + .fail + .warning + .notVerifiable + .errors + .notApplicable) > 0 or true)
      | pad(.key; 26) + " " + .value.status + "  (pass=\(.value.counts.pass) fail=\(.value.counts.fail) warn=\(.value.counts.warning) nv=\(.value.counts.notVerifiable) err=\(.value.counts.errors))"),
    "```",
    "",
    "Status roll-up: FAIL > ERROR > WARNING > NOT_VERIFIABLE > PASS. A domain is only PASS when every evaluated control passed and nothing was unverifiable.",
    "",
    "## Critical Findings",
    "",
    ([$F[] | select(.severity == "CRITICAL" and (.status == "FAIL" or .status == "WARNING"))] as $c
      | if ($c | length) == 0 then "_None._" else (fhdr, ($c | sort_by(.control) | .[0:$max][] | frow), (if ($c | length) > $max then "", "_\(($c | length) - $max) more in findings.csv_" else empty end)) end),
    "",
    "## High Findings",
    "",
    ([$F[] | select(.severity == "HIGH" and (.status == "FAIL" or .status == "WARNING"))] as $c
      | if ($c | length) == 0 then "_None._" else (fhdr, ($c | sort_by(.control) | .[0:$max][] | frow), (if ($c | length) > $max then "", "_\(($c | length) - $max) more in findings.csv_" else empty end)) end),
    "",
    "## Not Verifiable (HIGH / MEDIUM)",
    "",
    ([$F[] | select(.status == "NOT_VERIFIABLE" and (.severity == "HIGH" or .severity == "MEDIUM" or .severity == "CRITICAL"))] as $c
      | if ($c | length) == 0 then "_None._"
        else ("| Control | Resource | Reason |", "|---|---|---|", ($c | sort_by(.control) | .[0:$max][] | "| " + ([.control, (.resourceName | trunc(60)), (.reason | trunc(260))] | map(md) | join(" | ")) + " |"),
              (if ($c | length) > $max then "", "_\(($c | length) - $max) more in findings.csv_" else empty end)) end),
    "",
    "## Architecture Path Evaluation",
    "",
    "A diagnostic setting alone does not prove the required architecture. Paths below combine the evidence of each hop.",
    "",
    "### Log Analytics Workspaces -> Event Hub -> Cribl",
    "",
    "```text",
    ( $law[] | select(.auditStatus == "OK") | . as $L
      | ([$F[] | select(.control == "EH-002" and .resourceId == $L.id)]) as $paths
      | "LAW " + $L.name + "  [" + $L.subscriptionName + "]  retention=" + ($L.retentionInDays | tostring) + "d",
        "   |",
        "   +-- " + pad("HOT RETENTION (LAW-001/002)"; 44) + " " + ([$F[] | select((.control == "LAW-001" or .control == "LAW-002") and ((.resourceId | lc) | startswith($L.id)))] | if length == 0 then "N/A" else worst_status end),
        "   +-- " + pad("DATA EXPORT (LAW-003)"; 44) + " " + st("LAW-003"; $L.id),
        "   |       active=" + (($L.activeTablesCount // "?") | tostring) + " exportedToEH=" + ($L.exportedToEventHub | length | tostring)
                  + " missing=" + ($L.missingExports | length | tostring) + " missing(unconfirmed)=" + ($L.missingExportsUnconfirmed | length | tostring)
                  + " unsupported=" + ($L.unsupportedActive | length | tostring) + "   (LAW-004: " + st("LAW-004"; $L.id) + ")",
        ( if ($paths | length) == 0 then "   |       +-- (no Event Hub destination)" + " " + ("-" * 20) + " FAIL"
          else ($paths[] | . as $p | ($p.resourceName | split(" -> ")[1] // "?") as $dst
                | "   |       +-- " + pad(($dst | trunc(38)); 38) + " " + $p.status,
                  "   |                |   delivery (EH-005) ........ " + ([$F[] | select(.control == "EH-005" and .resourceName == $p.resourceName)] | if length == 0 then "N/A" else worst_status end),
                  "   |                +-- " + pad("CRIBL (EH-004)"; 30) + " " + ([$F[] | select(.control == "EH-004" and .resourceName == $p.resourceName)] | if length == 0 then "N/A" else worst_status end),
                  "   |                         +-- ELASTICSEARCH / SOC ---- NOT_VERIFIABLE") end ),
        "" ),
    "```",
    "",
    "### Subscription Activity Logs",
    "",
    "```text",
    ( $act[] | . as $a | ("/subscriptions/" + $a.subscriptionId) as $rid
      | "SUBSCRIPTION " + ($a.subscriptionName // $a.subscriptionId) + (if $a.auditStatus != "OK" then "  (" + $a.auditStatus + ")" else "" end),
        "   +-- " + pad("LAW"; 24) + " " + st("ACT-001"; $rid) + "  " + (($a.workspaces // []) | map(name_of) | join(", ")),
        "   +-- " + pad("STORAGE / WORM"; 24) + " " + st("ACT-002"; $rid) + "  " + (($a.storageAccounts // []) | map(name_of) | join(", ")),
        "   +-- " + pad("EVENT HUB"; 24) + " " + st("ACT-003"; $rid),
        "" ),
    "```",
    "",
    "### Entra ID",
    "",
    "```text",
    ( ["ENTRA-001", "ENTRA-002", "ENTRA-003", "ENTRA-004", "ENTRA-005", "ENTRA-006", "ENTRA-007", "ENTRA-008"][] as $c
      | ([$F[] | select(.control == $c)] | first) as $x | pad($c + " " + ($x.title // ""); 56) + " " + ($x.status // "N/A") ),
    "```",
    "",
    "### Critical resource types (LAW / archive / Event Hub hops)",
    "",
    ( [$diag[] | select(.auditStatus == "OK" and .isCritical and ((.logCategories // []) | length) > 0)] as $cr
      | if ($cr | length) == 0 then "_No critical-type resources with log categories found._"
        else ("| Resource | Type | Coverage | LAW (LOG-003) | Archive WORM (LOG-005) | Direct EH | LAW export (LAW-003) |", "|---|---|---|---|---|---|---|",
              ($cr | sort_by(.type, .name) | .[0:$max][] | . as $r
               | "| " + ([ ($r.name | trunc(50)), ($r.type | sub("^microsoft\\."; "")), $r.coverage,
                           (if ($r.coverage == "NONE" or $r.coverage == "METRICS_ONLY") then "FAIL (LOG-001: " + $r.coverage + ")" else st("LOG-003"; $r.id) end),
                           (if (($r.storageAccounts // []) | length) == 0 then "none" else st("LOG-005"; $r.id) end),
                           (if (($r.categoriesToEventHub // []) | length) > 0 then "yes" else "no" end),
                           (($r.workspaces // []) | map(. as $w | ($LM[$w] // null) | if . == null then "out-of-scope" else .name + ":" + st("LAW-003"; .id) end) | join(", ") | if . == "" then "-" else . end) ]
                         | map(md) | join(" | ")) + " |"),
              (if ($cr | length) > $max then "", "_\(($cr | length) - $max) more in diagnostic-settings.csv_" else empty end)) end ),
    "",
    "## Log Analytics Workspaces",
    "",
    (if ($law | length) == 0 then "_No workspaces found._" else
      ("| Workspace | Subscription | SKU | Retention | Daily cap | Tables | Active | EH export rules | Exported to EH | Missing | AzureDiagnostics |", "|---|---|---|---|---|---|---|---|---|---|---|",
       ($law[] | "| " + ([.name, .subscriptionName, (.sku // ""), ((.retentionInDays // "?") | tostring), ((.dailyQuotaGb // "none") | tostring), ((.lawTablesCount // "?") | tostring),
                         ((.activeTablesCount // "?") | tostring), ((.enabledEventHubRules // 0) | tostring), ((.exportedToEventHub // []) | length | tostring),
                         (((.missingExports // []) + (.missingExportsUnconfirmed // [])) | length | tostring), ((.azureDiagnosticsActive // "?") | tostring)] | map(md) | join(" | ")) + " |")) end),
    "",
    "### LAW Data Export sets",
    "",
    ( $law[] | select(.auditStatus == "OK") |
      "**\(.name)**", "",
      "- EXPORTED_TO_EVENT_HUB (\(.exportedToEventHub | length)): \(.exportedToEventHub | join(", ") | md | trunc(1500))",
      "- ACTIVE_TABLES (\(.activeTablesCount // "unknown")): \(.activeTables | join(", ") | md | trunc(1500))",
      "- MISSING_EXPORTS (confirmed eligible): \(.missingExports | join(", ") | md | trunc(1500))",
      "- MISSING_EXPORTS (eligibility unconfirmed): \(.missingExportsUnconfirmed | join(", ") | md | trunc(1500))",
      "- UNSUPPORTED_EXPORTS (active): \(.unsupportedActive | join(", ") | md | trunc(1500))",
      "- Status: tables=\(.tablesStatus), usage=\(.usageStatus), exports=\(.exportsStatus)", "" ),
    "",
    "## WORM Archive Storage",
    "",
    (if ($sto | length) == 0 then "_No archive/logging storage accounts found._" else
      ("| Storage account | Referenced by | HNS | Versioning | Soft delete | WORM state | Min locked days | Containers evaluated |", "|---|---|---|---|---|---|---|---|",
       ($sto[] | "| " + ([.name, ((.reasons // []) | join(", ")), ((.isHnsEnabled // "?") | tostring), ((.blobVersioning // "?") | tostring),
                        (((.blobSoftDelete // false) and (.containerSoftDelete // false)) | tostring), (.wormState // .auditStatus),
                        ((.minImmutabilityDays // .accountImmutabilityPeriodDays // "-") | tostring), (((.containersEvaluated // 0) | tostring) + " (" + (.evaluationBasis // "-") + ")")] | map(md) | join(" | ")) + " |")) end),
    "",
    "WORM states: NO_IMMUTABILITY < UNLOCKED_IMMUTABILITY < LOCKED_IMMUTABILITY (period too short) < LEGAL_HOLD < LOCKED_AND_RETENTION_SUFFICIENT. Only the last one is PASS. `allowProtectedAppendWrites` alone never implies WORM compliance.",
    "",
    "## Databases",
    "",
    (if ($db | length) == 0 then "_No PostgreSQL/MySQL/SQL servers found._" else
      ("| Server | Engine | Auditing | Central LAW | Notes |", "|---|---|---|---|---|",
       ($db[] | . as $d | "| " + ([$d.name, $d.engine, st("DB-001"; $d.id), st("DB-002"; $d.id),
                (if $d.engine == "PostgreSQLFlexible" then "pgaudit.log=" + ($d.pgauditLog // "unset") elif $d.engine == "AzureSQL" then "state=" + ($d.auditState // "?") + ", storage=" + ($d.storageAccountName // "") elif $d.engine == "MySQLFlexible" then "audit_log_enabled=" + ($d.auditLogEnabled // "?") else ($d.auditError // "") end)] | map(md) | join(" | ")) + " |")) end),
    "",
    "## RBAC on Logging Infrastructure",
    "",
    (if ($rbac | length) == 0 then "_Not evaluated or no assignments._" else
      ("Assignments reviewed: \($rbac | length) (privileged, non-allow-listed: \([$rbac[] | select(.privileged and (.allowlisted | not))] | length); PIM eligible: \([$rbac[] | select(.assignmentType == "ELIGIBLE")] | length))", "",
       "| Scope | Role | Class | Principal type | Principal | Inheritance |", "|---|---|---|---|---|---|",
       ([$rbac[] | select(.privileged and (.allowlisted | not))] | sort_by(.scopeName) | .[0:$max][]
         | "| " + ([.scopeType + ":" + .scopeName, .roleName, .roleClass, .principalType, (.principalId + (if .principalDisplayName != "" then " (" + .principalDisplayName + ")" else "" end)), (.inheritance + " " + .assignmentType)] | map(md) | join(" | ")) + " |")) end),
    "",
    "## Audit Coverage Limitations",
    "",
    ($S.limitations[] | "- " + md),
    "",
    "## Remediation Examples - NOT EXECUTED",
    "",
    "> **REMEDIATION EXAMPLE - NOT EXECUTED.** The audit tool never runs these commands. Review, adapt and apply through change management. Locking immutability policies is irreversible.",
    "",
    "```bash",
    ( [$F[] | select(.status == "FAIL")] as $fails
      | ( [$fails[] | select(.control == "LOG-001" or .control == "LOG-003")] | .[0:$rmax][]
          | "# REMEDIATION EXAMPLE - NOT EXECUTED (\(.control)) \(.resourceName)",
            "az monitor diagnostic-settings create --name diag-central-soc --resource \"\(.resourceId)\" --workspace \"\($centralLaw)\" --export-to-resource-specific true --storage-account \"\($archive)\" --logs '\''[{\"categoryGroup\":\"allLogs\",\"enabled\":true}]'\'' --metrics '\''[{\"category\":\"AllMetrics\",\"enabled\":true}]'\''", "" ),
        ( [$fails[] | select(.control == "LAW-001")] | .[0:$rmax][]
          | "# REMEDIATION EXAMPLE - NOT EXECUTED (LAW-001) \(.resourceName)",
            "az monitor log-analytics workspace update --resource-group \"\(.resourceGroup)\" --workspace-name \"\(.resourceName)\" --retention-time \($hotMin)", "" ),
        ( [$fails[] | select(.control == "LAW-002" and (.resourceId | test("/tables/")))] | .[0:$rmax][]
          | "# REMEDIATION EXAMPLE - NOT EXECUTED (LAW-002) \(.resourceName)",
            (if (.expected | test("debug")) then $debugMax elif (.actual | test("^Table plan")) then -1 else $hotMin end) as $rt
            | if $rt == -1 then "# \(.resourceName): Basic/Auxiliary plan - change plan to Analytics (az monitor log-analytics workspace table update ... --plan Analytics) or reclassify the table", ""
              else "az monitor log-analytics workspace table update --resource-group \"\(.resourceGroup)\" --workspace-name \"\(.resourceName | split("/")[0])\" --name \"\(.resourceId | split("/") | last)\" --retention-time \($rt)", "" end ),
        ( [$fails[] | select(.control == "LAW-003")] | .[0:$rmax][] | . as $x | ($LM[.resourceId] // {}) as $L
          | "# REMEDIATION EXAMPLE - NOT EXECUTED (LAW-003) \(.resourceName)",
            "az monitor log-analytics workspace data-export create --resource-group \"\(.resourceGroup)\" --workspace-name \"\(.resourceName)\" --name export-to-soc-eventhub --destination \"\($secNs)\" --enable true --tables \(($L.exportableActive // ["<TABLE>"]) | .[0:40] | join(" "))", "" ),
        ( [$fails[] | select(.control == "LAW-004")] | .[0:$rmax][] | ($LM[.resourceId] // {}) as $L
          | "# REMEDIATION EXAMPLE - NOT EXECUTED (LAW-004) \(.resourceName): add missing tables to an existing Event Hub rule",
            "az monitor log-analytics workspace data-export update --resource-group \"\(.resourceGroup)\" --workspace-name \"\(.resourceName)\" --name \"\(($L.eventHubDestinations // [])[0].rule // "<RULE>")\" --tables \((((($L.eventHubDestinations // [])[0].tables // []) + ($L.missingExports // [])) | unique | join(" ")))", "" ),
        ( [$fails[] | select(.control == "ACT-001" or .control == "ACT-002")] | unique_by(.subscriptionId) | .[0:$rmax][]
          | "# REMEDIATION EXAMPLE - NOT EXECUTED (\(.control)) subscription \(.resourceName)",
            "az monitor diagnostic-settings subscription create --subscription \"\(.subscriptionId)\" --name activity-central-soc --location westeurope --workspace \"\($centralLaw)\" --storage-account \"\($archive)\" --logs '\''[{\"category\":\"Administrative\",\"enabled\":true},{\"category\":\"Security\",\"enabled\":true},{\"category\":\"Policy\",\"enabled\":true},{\"category\":\"ServiceHealth\",\"enabled\":true},{\"category\":\"Alert\",\"enabled\":true},{\"category\":\"Recommendation\",\"enabled\":true},{\"category\":\"Autoscale\",\"enabled\":true},{\"category\":\"ResourceHealth\",\"enabled\":true}]'\''", "" ),
        ( [$worm[] | select(.evaluated and (.wormState == "NO_IMMUTABILITY" or .wormState == "UNLOCKED_IMMUTABILITY" or .wormState == "LOCKED_IMMUTABILITY"))] | .[0:$rmax][]
          | if .wormState == "NO_IMMUTABILITY" then
              "# REMEDIATION EXAMPLE - NOT EXECUTED (ARC-004) \(.storageAccountName)/\(.container)",
              "az storage container immutability-policy create --account-name \"\(.storageAccountName)\" --container-name \"\(.container)\" --period \($target) --allow-protected-append-writes-all true --auth-mode login", ""
            elif .wormState == "UNLOCKED_IMMUTABILITY" then
              "# REMEDIATION EXAMPLE - NOT EXECUTED (ARC-005) \(.storageAccountName)/\(.container) - LOCKING IS IRREVERSIBLE",
              "az storage container immutability-policy lock --account-name \"\(.storageAccountName)\" --container-name \"\(.container)\" --if-match \"<ETAG_FROM_immutability-policy_show>\"", ""
            else
              "# REMEDIATION EXAMPLE - NOT EXECUTED (ARC-006) \(.storageAccountName)/\(.container): extend locked period",
              "az storage container immutability-policy extend --account-name \"\(.storageAccountName)\" --container-name \"\(.container)\" --period \($target) --if-match \"<ETAG>\"", "" end ),
        ( [$fails[] | select(.control == "DB-001" or .control == "DB-002")] | .[0:$rmax][]
          | if (.resourceType == "microsoft.sql/servers") then
              "# REMEDIATION EXAMPLE - NOT EXECUTED (\(.control)) \(.resourceName)",
              "az sql server audit-policy update --resource-group \"\(.resourceGroup)\" --name \"\(.resourceName)\" --state Enabled --log-analytics-target-state Enabled --log-analytics-workspace-resource-id \"\($centralLaw)\"", ""
            elif (.resourceType == "microsoft.dbforpostgresql/flexibleservers") then
              "# REMEDIATION EXAMPLE - NOT EXECUTED (\(.control)) \(.resourceName) (requires restart; then CREATE EXTENSION pgaudit per database)",
              "az postgres flexible-server parameter set --resource-group \"\(.resourceGroup)\" --server-name \"\(.resourceName)\" --name shared_preload_libraries --value pgaudit",
              "az postgres flexible-server parameter set --resource-group \"\(.resourceGroup)\" --server-name \"\(.resourceName)\" --name pgaudit.log --value \"ddl,write,role\"", ""
            else empty end ),
        ( [$fails[] | select(.control == "EH-002" and (.reason | test("trusted Microsoft services")))] | .[0:$rmax][]
          | "# REMEDIATION EXAMPLE - NOT EXECUTED (EH-002) allow trusted Microsoft services on destination namespace",
            "az eventhubs namespace network-rule-set update --resource-group \"<EH_RESOURCE_GROUP>\" --namespace-name \"\(.resourceName | split(" -> ")[1] | split("/")[0])\" --trusted-service-access-enabled true", "" ),
        ( [$fails[] | select(.control | startswith("ENTRA-"))] | .[0:1][]
          | "# REMEDIATION EXAMPLE - NOT EXECUTED (Entra) configure Entra ID diagnostic settings (portal: Entra ID > Monitoring > Diagnostic settings) or:",
            "az rest --method put --url \"https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/entra-to-soc?api-version=2017-04-01\" --body @entra-diagnostic-setting.json", "" )
    ),
    "```",
    "",
    "## Evidence",
    "",
    "- `findings.csv` / `summary.json`: every finding with expected vs. observed values and reproduction evidence (API call)",
    "- `diagnostic-settings.csv`, `law*.csv`, `event-hubs.csv`, `storage.csv`, `worm-policies.csv`, `rbac.csv`, `activity-log.csv`, `application-insights.csv`, `databases.csv`, `databricks.csv`",
    "- `errors.csv`: every failed Azure request (403/404/5xx/...) with the redacted error message",
    "- `raw/`: redacted raw ARM responses referenced by `evidenceFile`",
    "",
    "## Regulatory Mapping",
    "",
    "| Domain | Mapping (supporting evidence only) |", "|---|---|",
    "| Logging, retention, archive, streaming | DORA Art. 12 (logging; see RTS (EU) 2024/1774 Art. 12), ISO/IEC 27001:2022 A.8.15 Logging, A.5.28 Collection of evidence |",
    "| Access to logging infrastructure | ISO/IEC 27001:2022 A.5.15 Access control, A.8.2 Privileged access rights |"
  ' -r -n --slurpfile sum "$RUN_DIR/summary.json" --slurpfile law "$WORK/law_joined.jsonl" \
     --slurpfile act "$(merged activity)" --slurpfile sto "$(merged storage)" \
     --slurpfile eh "$(merged eventhubs)" --slurpfile db "$(merged databases)" \
     --slurpfile rbac "$(merged rbac)" --slurpfile worm "$(merged worm)" \
     --argjson max "$MD_MAX_FINDINGS" --argjson rmax "$REMEDIATION_MAX_EXAMPLES" \
     --arg centralRe "$CENTRAL_LAW_REGEX" --argjson hotMin "$HOT_RETENTION_MIN_DAYS" --argjson target "$ARCHIVE_RETENTION_TARGET_DAYS" \
     --argjson debugMax "$DEBUG_RETENTION_MAX_DAYS" --slurpfile diag "$WORK/diag_projection.jsonl" \
     > "$f" 2>"$WORK/md.err" || log_error "summary.md generation failed: $(head -c 400 "$WORK/md.err")"
}

generate_summary() {
  log_info ""
  log_info "Generating reports..."
  write_config_snapshot
  compute_metrics
  compute_limitations
  generate_csv
  generate_json
  generate_markdown
  mkdir -p "$RAW_DIR/records"
  cp "$WORK"/merged/*.jsonl "$RAW_DIR/records/" 2>/dev/null
  if [ "$DEBUG" != true ]; then rm -rf "$WORK"; LOG_FILE="$RUN_DIR/audit.log"; fi
  local p fl w nv e
  p="$(jq '.summary.pass' "$RUN_DIR/summary.json" 2>/dev/null)"; fl="$(jq '.summary.fail' "$RUN_DIR/summary.json" 2>/dev/null)"
  w="$(jq '.summary.warning' "$RUN_DIR/summary.json" 2>/dev/null)"; nv="$(jq '.summary.notVerifiable' "$RUN_DIR/summary.json" 2>/dev/null)"
  e="$(jq '.summary.errors' "$RUN_DIR/summary.json" 2>/dev/null)"
  log_info "PASS=$p FAIL=$fl WARNING=$w NOT_VERIFIABLE=$nv ERROR=$e"
  log_info "Reports: $RUN_DIR/summary.md | summary.json | findings.csv"
}

gate_exit_code() {
  local q
  case "$FAIL_ON" in
    none) echo 0; return ;;
    error) q='[.findings[] | select(.status == "ERROR" or .status == "FAIL")] | length' ;;
    fail) q='[.findings[] | select(.status == "FAIL")] | length' ;;
    high) q='[.findings[] | select(.status == "FAIL" and (.severity == "HIGH" or .severity == "CRITICAL"))] | length' ;;
    critical) q='[.findings[] | select(.status == "FAIL" and .severity == "CRITICAL")] | length' ;;
  esac
  if [ "$(jq "$q" "$RUN_DIR/summary.json" 2>/dev/null || echo 1)" -gt 0 ]; then echo 1; else echo 0; fi
}

REPORTING=false
on_interrupt() {
  [ "$REPORTING" = true ] && exit 130
  REPORTING=true
  INTERRUPTED=true
  log_warn "Interrupted - stopping workers and writing partial reports..."
  local p
  for p in $(jobs -p); do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  [ -n "$WORK" ] && [ -d "$WORK" ] && { [ -f "$WORK/cribl.json" ] || echo '{"configured": false}' > "$WORK/cribl.json"; generate_summary; }
  exit 130
}

# =============================================================================
# MAIN
# =============================================================================
main() {
  parse_args "$@"
  setup_colors
  check_dependencies
  init_output
  trap on_interrupt INT TERM
  log_info "$TOOL_NAME $TOOL_VERSION (read-only)"
  get_tenant
  get_subscriptions
  build_diag_cfg; build_law_cfg; build_eh_cfg; build_sto_cfg; build_rbac_cfg; build_corr_cfg
  echo '{"configured": false}' > "$WORK/cribl.json"

  local total idx=0 sub name
  total="$(jq '[.[] | select(.include)] | length' "$WORK/subscriptions.json")"
  while IFS=$'\t' read -r sub name; do
    [ -n "$sub" ] || continue
    idx=$((idx + 1))
    audit_subscription "$idx" "$total" "$sub" "$name"
  done < <(jq -r '.[] | select(.include) | "\(.id)\t\(.name)"' "$WORK/subscriptions.json")

  log_info ""
  audit_entra
  ensure_referenced_eventhubs
  audit_worm
  audit_rbac
  verify_cribl
  correlate
  REPORTING=true
  generate_summary
  exit "$(gate_exit_code)"
}

main "$@"
