const API_BASE = "/api";
const DEFAULT_TIMEOUT_MS = 30_000;
const API_KEY_STORAGE = "ioc-platform-api-key";
export const AUTH_REQUIRED_EVENT = "ioc-auth-required";
let runtimeApiKey = "";

if (typeof window !== "undefined") {
  try {
    runtimeApiKey = window.sessionStorage.getItem(API_KEY_STORAGE) ?? "";
  } catch {
    runtimeApiKey = "";
  }
}

export function setRuntimeApiKey(value: string): void {
  runtimeApiKey = value.trim();
  try {
    window.sessionStorage.setItem(API_KEY_STORAGE, runtimeApiKey);
  } catch {
    return;
  }
}

export function clearRuntimeApiKey(): void {
  runtimeApiKey = "";
  try {
    window.sessionStorage.removeItem(API_KEY_STORAGE);
  } catch {
    return;
  }
}


export class ApiError extends Error {
  status: number;
  detail?: string;
  retryAfterSeconds?: number;

  constructor(message: string, status: number, detail?: string, retryAfterSeconds?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** `detail` marker for a request that never reached the backend. */
export const NETWORK_ERROR_DETAIL = "network";
/** `detail` marker for a request aborted by the client-side timeout. */
export const TIMEOUT_DETAIL = "timeout";

function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds;
  const date = Date.parse(value);
  if (Number.isFinite(date)) return Math.max(0, Math.round((date - Date.now()) / 1000));
  return undefined;
}

/**
 * Read a human-readable error detail from a failed response. FastAPI errors are
 * JSON (`{"detail": ...}`), but the auth and rate-limit middleware answer with
 * text/plain bodies, which used to be discarded — leaving the analyst with a bare
 * "Request failed: 429".
 */
async function readErrorDetail(res: Response): Promise<string | undefined> {
  let text = "";
  try {
    text = await res.text();
  } catch {
    return undefined;
  }
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  try {
    const body = JSON.parse(trimmed) as unknown;
    if (body && typeof body === "object" && "detail" in body) {
      const detail = (body as { detail: unknown }).detail;
      if (typeof detail === "string") return detail;
      if (Array.isArray(detail)) {
        const parts = detail
          .map((item) => (item && typeof item === "object" && "msg" in item ? String((item as { msg: unknown }).msg) : ""))
          .filter(Boolean);
        return parts.length ? parts.join("; ") : undefined;
      }
    }
    return undefined;
  } catch {
    // Plain-text body (middleware responses). Ignore HTML error pages.
    return trimmed.startsWith("<") ? undefined : trimmed.slice(0, 300);
  }
}

/** Analyst-facing message for a failed request, by status. */
function describeFailure(status: number, detail: string | undefined, retryAfter: number | undefined): string {
  const retry = retryAfter != null ? ` Retry in ${Math.round(retryAfter)}s.` : "";
  if (status === 401) return "Authentication required: enter the local API key for this instance.";
  if (status === 403) return detail || "This action is not permitted by the server configuration.";
  if (status === 404) return detail || "Not found on the server.";
  if (status === 429) {
    return `${detail || "Too many requests: the platform's lookup rate limit was reached."}${retry}`.trim();
  }
  if (status === 502 || status === 503 || status === 504) {
    return detail ? `Backend unavailable (${status}): ${detail}` : `Backend unavailable (HTTP ${status}). Check that the IOC Lookup Platform server is running.`;
  }
  if (status >= 500) return detail ? `Server error (${status}): ${detail}` : `Server error (HTTP ${status}).`;
  return detail || `Request failed (HTTP ${status}).`;
}

/** Best-effort human message for any error thrown by this module. */
export function errorMessage(error: unknown, fallback = "Request failed"): string {
  if (error instanceof ApiError) return error.message || error.detail || fallback;
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}

interface RequestOptions extends RequestInit {
  timeoutMs?: number;
}

export function apiHeaders(headers: HeadersInit = {}): Headers {
  const result = new Headers(headers);
  if (runtimeApiKey && !result.has("X-API-Key")) {
    result.set("X-API-Key", runtimeApiKey);
  }
  return result;
}


async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, ...init } = options;
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: apiHeaders(init.headers),
      signal: controller.signal,
    });
    if (!res.ok) {
      if (res.status === 401 && typeof window !== "undefined") {
        window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
      }
      const detail = await readErrorDetail(res);
      const retryAfter = parseRetryAfter(res.headers.get("Retry-After"));
      throw new ApiError(describeFailure(res.status, detail, retryAfter), res.status, detail, retryAfter);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError(`The server did not answer within ${Math.round(timeoutMs / 1000)}s.`, 0, TIMEOUT_DETAIL);
    }
    if (err instanceof TypeError) {
      // fetch() rejects with a TypeError when the backend is unreachable.
      throw new ApiError("Cannot reach the IOC Lookup Platform backend. Check that the server is running.", 0, NETWORK_ERROR_DETAIL);
    }
    if (err instanceof SyntaxError) {
      throw new ApiError("The server returned an unreadable response.", 0, "invalid_response");
    }
    throw err;
  } finally {
    window.clearTimeout(timer);
  }
}

export async function fetchProtectedImage(path: string): Promise<string> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
  const url = path.startsWith("/api/") ? path : `${API_BASE}${path}`;
  try {
    const res = await fetch(url, { headers: apiHeaders(), signal: controller.signal });
    if (!res.ok) {
      if (res.status === 401 && typeof window !== "undefined") {
        window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
      }
      throw new ApiError(`Image request failed: ${res.status}`, res.status);
    }
    return URL.createObjectURL(await res.blob());
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError("Image request timed out", 0, TIMEOUT_DETAIL);
    }
    throw err;
  } finally {
    window.clearTimeout(timer);
  }
}


export interface StageInfo {
  name: string;
  status: string;
  message: string;
  progress: number;
}

export interface TaskResponse {
  task_id: string;
  status: string;
  progress?: number;
  stages?: StageInfo[];
  ioc_value: string;
  error?: string;
}

export interface NormalizedResult {
  ioc: string;
  task_id?: string;

  ioc_type: string;
  assessment_domain?: string;
  domain_classification?: string | null;
  source: string;
  verdict: string;
  status: string;
  execution_state: string;
  provider_verdict?: string | null;
  normalized_verdict?: string;
  raw_score: number | null;
  confidence: string;
  detection_count?: number | null;
  total_engines?: number | null;
  cached?: boolean;
  cache_age?: number | null;
  observed_at?: string | null;
  expires_at?: string | null;
  source_timestamp?: string | null;
  cache_status?: string;
  cache_key?: string | null;
  cache_created_at?: string | null;
  retrieved_at?: string | null;
  freshness_class?: string | null;
  stale?: boolean;
  latency_ms?: number | null;
  queue_wait_ms?: number;
  network_latency_ms?: number | null;
  retry_count?: number;
  http_status?: number | null;
  retry_after_seconds?: number | null;
  request_made?: boolean;
  tags: string[];
  categories: string[];
  malware_family?: string;
  mitre_attck?: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  related_iocs?: [string, string][];
  source_link?: string;
  reports_count?: number;
  reports?: Record<string, unknown>[];
  raw_data?: Record<string, unknown>;
  provider_summary?: string;
  evidence_items?: Record<string, unknown>[];
  provenance_family?: string | null;
  source_record_id?: string | null;
  record_fingerprint?: string | null;
  source_independence_group?: string | null;
  evidence_hash?: string | null;
  duplicate_of?: string | null;
  vulnerability_status?: string | null;
  severity?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  epss_score?: number | null;
  cwe?: string[];
  affected_products?: string[];
  published_at?: string | null;
  modified_at?: string | null;
  exploit_status?: string | null;
  references?: string[];
  samples?: string[];
  dropped_files?: string[];
  registry_keys?: string[];
  network_iocs?: [string, string][];
  process_tree?: string;
  ssdeep?: string;
  tlsh?: string;
}

export interface GeoIPInfo {
  country?: string;
  country_code?: string;
  city?: string;
  region?: string;
  timezone?: string;
  asn?: string;
  asn_name?: string;
  isp?: string;
  org?: string;
  latitude?: number;
  longitude?: number;
  is_vpn?: boolean;
  is_tor?: boolean;
  is_proxy?: boolean;
  is_datacenter?: boolean;
  is_anycast?: boolean;
}

export interface WhoisInfo {
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  updated_date?: string;
  nameservers?: string[];
  status_codes?: string[];
  registrant_country?: string;
  dnssec?: string;
  domain_age_days?: number;
  is_newly_registered?: boolean;
  abuse_email?: string;
  org?: string;
  privacy_protected?: boolean;
  fallback_tier_used?: number;
}

export interface DNSInfo {
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
  txt: string[];
  cname: string[];
}

export interface SSLInfo {
  subject?: string;
  issuer?: string;
  serial?: string;
  not_before?: string;
  not_after?: string;
  fingerprint?: string;
  subject_alt_names: string[];
  is_self_signed: boolean;
  is_expired: boolean;
  is_wildcard: boolean;
  days_remaining?: number;
}

export interface ReverseDNSInfo {
  hostnames: string[];
}

export interface SubdomainInfo {
  subdomains: string[];
}

export interface PassiveDNSInfo {
  records: Record<string, unknown>[];
}

export interface CVEInfo {
  is_in_kev: boolean;
  kev_date_added: string;
  epss_score?: number;
  epss_percentile?: number;
  cvss_score?: number;
  cvss_severity?: string;
  cvss_vector: string;
  cvss_attack_vector: string;
  cvss_complexity: string;
  cvss_privileges_required: string;
  cvss_user_interaction: string;
  cwe: string[];
  references: string[];
  public_exploits_exist: boolean;
  exploit_sources: string[];
  poc_available: boolean;
  affected_products: string[];
  cvss_breakdown?: Record<string, unknown>;
  vulnerability_status?: string | null;
  published_at?: string | null;
  modified_at?: string | null;
  exploit_status?: string | null;
}

export interface BreachInfo {
  breach_count?: number;
  breach_names: string[];
  most_recent_breach: string;
  exposed_data_types: string[];
  source: string;
}

export interface FaviconInfo {
  favicon_hash: number;
  favicon_url: string;
}

export interface EmailSecurityInfo {
  spf: string;
  dkim: string;
  dmarc: string;
}

export interface HostIntelligence {
  open_ports: number[];
  port_services: Record<number, string>;
  unpatched_cves: string[];
  cpes: string[];
  tags: string[];
  hostnames: string[];
  source: string;
}

export interface WebPreviewInfo {
  screenshot_url?: string;
  page_title?: string;
  server?: string;
  language?: string;
  domain_age_days?: number;
  tls_issuer?: string;
  tls_valid_days?: number;
  asn_name?: string;
  detected_brands: string[];
  detected_technologies: string[];
  mime_type?: string;
  scan_uuid?: string;
}

export interface InfostealerIntel {
  total_employee_compromises: number;
  total_client_compromises: number;
  top_corporate_services: string[];
  top_external_services: string[];
  stealer_families: Record<string, number>;
  password_strength_weak_pct?: number;
  password_strength_strong_pct?: number;
  total_compromised_urls?: number;
  date_range?: string;
}

export interface AbuseReport {
  reported_at: string;
  reporter_country?: string;
  comment?: string;
  categories: string[];
  category_names: string[];
}

// ─── Context-based enrichment payloads (enrichment.extra.*) ───
// The backend enriches "context" IOC types into structured objects under
// `extra`. These are typed so the Investigation view can render dedicated
// cards instead of forcing the analyst into the Sources tab.
export interface AsnContext {
  resource: string;
  holder?: string;
  announced_prefix_count?: number;
  announced_prefixes?: { prefix?: string; timelines?: unknown[] }[];
  block?: Record<string, unknown>;
}

export interface MitreAttackContext {
  id: string;
  kind?: "tactic" | "technique" | string;
  title?: string;
  description?: string;
  url?: string;
}

export interface HostArtifactContext {
  value: string;
  type: string;
  server?: string;
  pipe_name?: string;
  hive?: string;
  key_path?: string;
  depth?: number;
  namespace?: string;
  name?: string;
}

export interface FilenameContext {
  value: string;
  extension?: string;
  category?: string;
  double_extension?: boolean;
  component_extensions?: string[];
}

export interface FilePathContext {
  value: string;
  os?: string;
  directory?: string;
  filename?: string;
  extension?: string;
  suspicious_location?: boolean;
  location_marker?: string;
}

export interface UserAgentContext {
  value: string;
  client?: string;
  platform?: string;
  is_automation?: boolean;
}

export interface MacContext {
  value: string;
  oui?: string;
  vendor?: string;
  locally_administered?: boolean;
  multicast?: boolean;
  virtualization?: boolean;
}

export interface HashResultEntry {
  filename?: string;
  size?: string | number;
  mime?: string;
  source?: string;
  database?: string;
  trust?: unknown;
  md5?: string;
  sha1?: string;
  sha256?: string;
  ssdeep?: string;
  tlsh?: string;
}

export interface SsdeepContext {
  block_size?: number | null;
  first_chunk_length?: number;
  second_chunk_length?: number;
  alphabet?: string;
}

export interface CryptoContext {
  address: string;
  hash160?: string;
  n_tx?: number;
  total_received_btc?: number;
  total_sent_btc?: number;
  final_balance_btc?: number;
  balance_eth?: number;
  transaction_count?: number;
  recent_transactions?: Record<string, unknown>[];
}

// Etherscan address-page + V2 API wallet context (backend etherscan_page.py).
export interface EthParty {
  address?: string | null;
  label?: string | null;
}

export interface EthTxRef {
  tx_hash?: string | null;
  age?: string;
}

export interface EthLabel {
  name: string;
  slug?: string;
  description?: string;
}

export interface EthToken {
  name: string;
  symbol?: string | null;
  standard?: string | null;
  contract?: string | null;
  amount?: number | null;
  value_usd?: number | null;
  price_usd?: number | null;
}

export interface EthChainHolding {
  chain: string;
  chain_id?: string;
  token_count?: number | null;
  value_usd: number;
  share_pct?: number | null;
  share_below_pct?: boolean;
  native_symbol?: string;
  native_balance?: number;
}

export interface EthTransaction {
  hash?: string | null;
  method?: string | null;
  block?: number | null;
  time?: number | null;
  datetime_utc?: string | null;
  direction?: "IN" | "OUT" | "SELF" | string | null;
  from?: EthParty;
  to?: EthParty;
  value_eth?: number | null;
  value_usd?: number | null;
  fee_eth?: number | null;
  failed?: boolean;
}

export interface EthCounterparty {
  address: string;
  label?: string | null;
  tx_count: number;
}

export interface EthereumContext {
  address: string;
  account_type?: "address" | "contract";
  public_name_tag?: string;
  ens_name?: string;
  website?: string;
  labels?: EthLabel[];
  risk_labels?: string[];
  warnings?: string[];
  balance_eth?: number | null;
  balance_usd?: number | null;
  eth_price_usd?: number | null;
  token_holdings_usd?: number | null;
  token_holdings_is_lower_bound?: boolean;
  token_count?: number | null;
  token_list_size?: number;
  tokens?: EthToken[];
  multichain_portfolio_usd?: number | null;
  multichain_address_count?: number | null;
  net_worth_eth?: number | null;
  active_chain_count?: number;
  chains?: EthChainHolding[];
  multichain_source?: "etherscan_page" | "etherscan_v2_native";
  multichain_chains_checked?: number;
  multichain_chains_unsupported?: string[];
  funded_by?: EthParty & EthTxRef;
  contract_creator?: EthParty & EthTxRef;
  token_tracker?: string;
  latest_tx_sent?: EthTxRef;
  first_tx_sent?: EthTxRef;
  transaction_count?: number | null;
  transaction_count_is_lower_bound?: boolean;
  pending_transactions?: number | null;
  recent_transactions?: EthTransaction[];
  unique_counterparties?: number;
  tagged_counterparties?: EthCounterparty[];
  risky_counterparties?: EthCounterparty[];
  data_sources?: string[];
  source_link?: string;
}

export interface EnrichmentExtra {
  bitcoin?: CryptoContext;
  ethereum?: EthereumContext;
  asn?: AsnContext;
  mitre_attack?: MitreAttackContext;
  host_artifact?: HostArtifactContext;
  filename?: FilenameContext;
  file_path?: FilePathContext;
  user_agent?: UserAgentContext;
  mac?: MacContext;
  hash_results?: HashResultEntry[];
  ssdeep?: SsdeepContext;
  [key: string]: unknown;
}

export interface EnrichmentData {
  geoip?: GeoIPInfo;
  open_ports: number[];
  whois?: WhoisInfo;
  dns?: DNSInfo;
  ssl?: SSLInfo;
  reverse_dns?: ReverseDNSInfo;
  subdomains?: SubdomainInfo;
  cve?: CVEInfo;
  breach?: BreachInfo;
  favicon?: FaviconInfo;
  email_security?: EmailSecurityInfo;
  passive_dns?: PassiveDNSInfo;
  redirect_chain: Record<string, unknown>[];
  url_preview: Record<string, unknown>;
  extra: EnrichmentExtra;
  relationships: Relationship[];
  completeness: Record<string, string>;
  analysis_notes?: string[];
  host_intel?: HostIntelligence;
  web_preview?: WebPreviewInfo;
  infostealer?: InfostealerIntel;
  abuse_reports?: AbuseReport[];
  hosting_ip_intel?: Record<string, unknown>;
  malware_urls?: string[];
  associated_hashes?: string[];
}

export interface SourceWeight {
  name: string;
  weight: number;
  verdict: string;
  score: number | null;
  confidence: string | null;
}

export interface CompositeScore {
  score: number;
  verdict: string;
  confidence: string;
  sources_contributing: number;
  source_breakdown: SourceWeight[];
  malicious_sources?: number;
  suspicious_sources?: number;
  clean_sources?: number;
  agreement?: number;
}

export interface CacheMetadata {
  cached: boolean;
  cache_age?: number | null;
  observed_at?: string | null;
  expires_at?: string | null;
  source_timestamp?: string | null;
  status: string;
}

export interface EvidenceObservation {
  source: string;
  status: string;
  execution_state: string;
  provider_verdict?: string | null;
  normalized_verdict?: string;
  assessment_domain?: string;
  verdict: string;
  role: string;
  evidence_class: string;
  weight: number;
  normalized_signal: number;
  contribution: string;
  confidence: string;
  reason: string;
  detection_count?: number | null;
  total_engines?: number | null;
  cached?: boolean;
  cache_age?: number | null;
  observed_at?: string | null;
  expires_at?: string | null;
  source_timestamp?: string | null;
  cache_status?: string;
  freshness_class?: string;
  stale?: boolean;
  latency_ms?: number | null;
  retry_count?: number;
  http_status?: number | null;
  retry_after_seconds?: number | null;
  request_made?: boolean;
  cache_metadata?: CacheMetadata;
  reports_count?: number | null;
  malware_family?: string | null;
  tags: string[];
  categories: string[];
  provenance?: string | null;
  evidence_hash?: string | null;
  source_record_id?: string | null;
  provenance_family?: string | null;
  source_independence_group?: string | null;
  duplicate_of?: string | null;
  evidence_items?: Record<string, unknown>[];
  metadata: Record<string, unknown>;
}

export interface IOCAssessment {
  ioc: string;
  task_id?: string;

  normalized_ioc?: string | null;
  ioc_type: string;
  assessment_domain?: string;
  classification?: string | null;
  final_verdict: string;
  risk_score?: number;
  confidence_score?: number;
  confidence: string;
  normalized_score: number;
  evidence_strength: number;
  coverage: number;
  needs_review: boolean;
  assessment_status?: string;
  review_reasons?: string[];
  freshness?: string;
  evidence_counts?: Record<string, number>;
  cache_status: string;
  evidence_summary: Record<string, unknown>;
  provider_breakdown: EvidenceObservation[];
  provider_plan?: Record<string, unknown>[];
  provider_health: ProviderHealth[];
  relationships?: Relationship[];
  malicious_sources: string[];
  suspicious_sources: string[];
  clean_sources: string[];
  unknown_sources: string[];
  not_found_sources: string[];
  rate_limited_sources: string[];
  unavailable_sources: string[];
  error_sources: string[];
  strongest_evidence: EvidenceObservation[];
  supporting_evidence: EvidenceObservation[];
  conflicting_evidence: EvidenceObservation[];
  context: string[];
  malware_families: string[];
  mitre_attck: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  reason: string;
  analyst_review_recommended: boolean;
  negative_evidence?: EvidenceObservation[];
  techniques?: Record<string, unknown>[];
  vulnerabilities?: Record<string, unknown>[];
  timestamps?: Record<string, unknown>;
  provider_summary?: Record<string, unknown>[];
  provider_health_summary?: Record<string, unknown>[];
  provenance?: Record<string, unknown>[];
  assessment_engine_version?: string;
  normalization_version?: string;
  scoring_policy_version?: string;
  provider_config_version?: string;
  analyzed_at?: string | null;
}

export interface ProviderHealth {
  source: string;
  request_count: number;
  success_count: number;
  failure_count: number;
  rate_limit_count: number;
  timeout_count: number;
  error_count: number;
  unavailable_count: number;
  not_found_count: number;
  invalid_request_count: number;
  retry_count: number;
  cache_hit_count: number;
  cache_miss_count: number;
  total_latency_ms: number;
  average_latency_ms: number;
  queue_wait_ms?: number;
  average_queue_wait_ms?: number;
  total_latency?: number;
  average_latency?: number;
  queue_wait?: number;
  last_execution_state: string;
}

export interface Relationship {
  source_ioc?: string;
  target_ioc?: string;
  relationship?: string;
  via_source?: string;
  [key: string]: unknown;
}

export interface LookupResponse {
  input: string;
  task_id?: string;
  normalized: string;

  ioc_type: string;
  password_prehashed?: boolean;
  composite: CompositeScore;
  final_assessment?: IOCAssessment | null;
  provider_health?: ProviderHealth[];
  enrichment: EnrichmentData;
  results: NormalizedResult[];
  relationships: Relationship[];
  executive_summary: string;
}

export interface SourceInventoryItem {
  name: string;
  supported_types: string[];
  public_without_key: boolean;
  requires_key: boolean;
  configured: boolean;
  available: boolean;
  enabled_by_policy: boolean;
  credential_env?: string;
  credential_source: string;
  rate_limit_per_minute: number;
  rate_limit_per_day: number;
  operations?: string[];
  evidence_roles?: string[];
  provenance_family?: string;
  reliability?: number;
  produces_reputation?: boolean;
  produces_vulnerability_intelligence?: boolean;
  produces_infrastructure_context?: boolean;
  produces_metadata?: boolean;
  produces_relationships?: boolean;
  cache_ttl_seconds?: number | null;
}

export interface KeyHealthResponse {
  keys: Record<string, boolean>;
  active_providers: number;
  total_providers: number;
  required_keys?: Record<string, boolean>;
  missing_keys: string[];
  public_providers?: string[];
}

export interface RawLookupResponse {
  ioc: string;
  ioc_type: string;
  provider_count: number;
  providers: Array<{
    source: string;
    execution_state: string;
    verdict: string;
    provider_verdict?: string | null;
    provider_summary?: string;
    raw_data?: Record<string, unknown>;
  }>;
}

export interface SourceInventory {
  sources: SourceInventoryItem[];
  count: number;
  available_count: number;
  credential_configured_count: number;
}

export async function lookupIOC(value: string, iocType?: string, options?: { refresh?: boolean }): Promise<TaskResponse> {
  const body: Record<string, string | boolean> = { ioc: value };
  if (iocType) body.ioc_type = iocType;
  if (options?.refresh) body.refresh = true;
  return request<TaskResponse>("/lookup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function getSourceInventory(): Promise<SourceInventory> {
  return request<SourceInventory>("/sources");
}

export async function getKeyHealth(): Promise<KeyHealthResponse> {
  return request<KeyHealthResponse>("/health/keys");
}

export async function getRawLookup(ioc: string): Promise<RawLookupResponse> {
  return request<RawLookupResponse>(`/lookup/${encodeURIComponent(ioc)}/raw`, { timeoutMs: 30_000 });
}

export async function getTaskStatus(taskId: string): Promise<TaskResponse> {
  return request<TaskResponse>(`/tasks/${taskId}`);
}

export async function getTaskResult(taskId: string): Promise<LookupResponse> {
  try {
    return await request<LookupResponse>(`/tasks/${taskId}/result`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 425) throw new ApiError("not_ready", 425);
    throw err;
  }
}

export async function cancelTask(taskId: string): Promise<{ task_id: string; status: string }> {
  return request(`/tasks/${taskId}/cancel`, { method: "POST" });
}

// --- Batch ---

export interface BatchSubtask {
  task_id: string;
  ioc_value: string;
  status: string;
  progress: number;
  error?: string;
  final_verdict?: string | null;
  confidence?: string | null;
  coverage?: number | null;
  needs_review?: boolean | null;
}

export interface BatchStatus {
  batch_id: string;
  status: string;
  progress: number;
  total: number;
  completed: number;
  active_iocs?: string[];
  expected_lookups: number;
  completed_lookups: number;
  successful_lookups: number;
  not_found_lookups: number;
  rate_limited_lookups: number;
  timeout_lookups: number;
  failed_lookups: number;
  not_applicable_lookups?: number;
  batch_deadline_exceeded?: number;
  provider_health?: ProviderHealth[];
  subtasks: BatchSubtask[];
  error?: string;
}

export interface BatchResultSummary {
  malicious: number;
  /** Credentials/addresses found in a breach corpus. Exposure, not proven malice. */
  breached?: number;
  suspicious: number;
  clean: number;
  unknown: number;
  error: number;
  context_only?: number;
  vulnerability?: number;
  attack_technique?: number;
}


export interface BatchResultItem extends NormalizedResult {
  _ioc?: string;
}

export interface BatchResult {
  batch_id: string;
  status?: string;
  total: number;
  completed: number;
  expected_lookups: number;
  completed_lookups: number;
  successful_lookups: number;
  not_found_lookups: number;
  rate_limited_lookups: number;
  timeout_lookups: number;
  failed_lookups: number;
  not_applicable_lookups?: number;
  batch_deadline_exceeded?: number;
  provider_health?: ProviderHealth[];
  summary: BatchResultSummary;
  results: BatchResultItem[];
  relationships: Relationship[];
  assessments?: IOCAssessment[];
  final_results?: IOCAssessment[];
  assessment_distribution?: Record<string, number>;
  execution_health?: Record<string, number>;
}

export interface SavedBatch {
  batch_id: string;
  total: number;
  completed: number;
  created_at?: string | null;
  summary?: Record<string, number>;
  result?: BatchResult;
}

/**
 * Fetch batch history from the backend SQLite database.
 * Falls back to empty array on error.
 */
export async function getBatchesFromServer(): Promise<SavedBatch[]> {
  try {
    return await request<SavedBatch[]>("/batches");
  } catch {
    return [];
  }
}

/**
 * @deprecated Batches are now auto-persisted server-side on completion.
 * This function is kept for backward compatibility but is a no-op.
 */
export function saveBatchHistory(_result: BatchResult): void {
  // No-op: server persists batches in SQLite automatically.
}

/**
 * Delete a batch from the server database.
 */
export async function deleteBatchFromServer(batchId: string): Promise<void> {
  await request(`/batch/${batchId}`, { method: "DELETE" });
}

// Legacy localStorage compat — kept for smooth migration
const SAVED_BATCHES_KEY = "ioc-platform.batch-history.v1";
export function getSavedBatches(): SavedBatch[] {
  try { return JSON.parse(localStorage.getItem(SAVED_BATCHES_KEY) || "[]") as SavedBatch[]; } catch { return []; }
}
export function deleteSavedBatch(batchId: string): void {
  localStorage.setItem(SAVED_BATCHES_KEY, JSON.stringify(getSavedBatches().filter((item) => item.batch_id !== batchId)));
}

export async function startBatch(iocs: string[]): Promise<{ batch_id: string; total: number; status: string }> {
  return request("/batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ iocs }),
  });
}

export async function cancelBatch(batchId: string): Promise<{ batch_id: string; status: string }> {
  return request(`/batch/${batchId}/cancel`, { method: "POST" });
}

export async function getBatchStatus(batchId: string): Promise<BatchStatus> {
  return request<BatchStatus>(`/batch/${batchId}`);
}

export async function getBatchResult(batchId: string): Promise<BatchResult> {
  try {
    return await request<BatchResult>(`/batch/${batchId}/result`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 425) throw new ApiError("not_ready", 425);
    throw err;
  }
}

export async function uploadBatchFile(file: File): Promise<{ batch_id: string; total: number; status: string }> {
  const form = new FormData();
  form.append("file", file);
  return request("/batch/upload", { method: "POST", body: form });
}

export type BatchSSEEventName = "batch_started" | "progress" | "batch_done" | "heartbeat" | string;

export interface BatchSSEEvent {
  event: BatchSSEEventName;
  data: Record<string, unknown>;
}

export async function streamBatchProgress(
  batchId: string,
  onEvent: (event: BatchSSEEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const res = await fetch(`${API_BASE}/batch/${batchId}/stream`, { signal, headers: apiHeaders() });
  if (!res.ok || !res.body) throw new ApiError(`Stream failed: ${res.status}`, res.status);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = buffer.split("\n\n");
      buffer = events.pop() ?? "";
      for (const block of events) {
        const event = parseSSE(block);
        if (event) onEvent(event);
      }
    }
  } finally {
    reader.releaseLock();
  }
}

function parseSSE(block: string): BatchSSEEvent | null {
  let event = "message";
  let dataRaw = "";
  for (const line of block.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) dataRaw += line.slice(5).trim();
  }
  if (!dataRaw) return null;
  let data: Record<string, unknown> = {};
  try {
    data = JSON.parse(dataRaw);
  } catch {
    return null;
  }
  return { event, data };
}

// --- Investigations ---

export interface InvestigationSummary {
  id: number;
  name: string;
  description: string;
  ioc_count: number;
  created_at: string;
  updated_at: string;
}

export interface InvestigationIOCEntry {
  id: number;
  ioc_id: number;
  value: string;
  ioc_type: string;
  notes: string;
  score: number | null;
  verdict: string | null;
  looked_up_at: string | null;
}

export interface InvestigationDetail {
  id: number;
  name: string;
  description: string;
  iocs: InvestigationIOCEntry[];
  created_at: string;
  updated_at: string;
}

export async function listInvestigations(): Promise<InvestigationSummary[]> {
  return request<InvestigationSummary[]>("/investigations");
}

export async function createInvestigation(name: string, description = ""): Promise<{ id: number; name: string }> {
  return request("/investigations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, description }),
  });
}

export async function getInvestigation(id: number): Promise<InvestigationDetail> {
  return request<InvestigationDetail>(`/investigations/${id}`);
}

export async function updateInvestigation(id: number, data: { name?: string; description?: string }): Promise<void> {
  await request<void>(`/investigations/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

export async function deleteInvestigation(id: number): Promise<void> {
  await request<void>(`/investigations/${id}`, { method: "DELETE" });
}

export async function addIOCToInvestigation(invId: number, ioc: string): Promise<void> {
  await request<void>(`/investigations/${invId}/iocs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ioc }),
  });
}

export async function updateIOCNotes(invId: number, iiId: number, notes: string): Promise<void> {
  await request<void>(`/investigations/${invId}/iocs/${iiId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ notes }),
  });
}

export async function removeIOCFromInvestigation(invId: number, iiId: number): Promise<void> {
  await request<void>(`/investigations/${invId}/iocs/${iiId}`, { method: "DELETE" });
}

// --- Recent ---

export interface RecentIOC {
  id: number;
  value: string;
  ioc_type: string;
  verdict: string | null;
  score: number | null;
  confidence: string | null;
  created_at: string | null;
  /** Optional authoritative final_assessment fields, when the backend provides them. */
  final_verdict?: string | null;
  final_score?: number | null;
  assessment_domain?: string | null;
}

export async function getRecentIOCs(): Promise<RecentIOC[]> {
  return request<RecentIOC[]>("/recent");
}

export async function getRecentIOCResult(id: number): Promise<LookupResponse> {
  return request<LookupResponse>(`/recent/${id}/result`);
}

export async function getStoredLookup(ioc: string): Promise<LookupResponse | null> {
  try {
    return await request<LookupResponse>(`/lookup/stored?ioc=${encodeURIComponent(ioc)}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

export async function getBatchIOCResult(batchId: string, ioc: string): Promise<LookupResponse> {
  return request<LookupResponse>(`/batch/${batchId}/ioc/${encodeURIComponent(ioc)}`);
}

export function buildLookupResponseFromBatch(
  iocValue: string,
  iocType: string,
  assessment?: IOCAssessment,
  results: BatchResultItem[] = [],
  relationships: Relationship[] = [],
  providerHealth: ProviderHealth[] = [],
  taskId?: string
): LookupResponse {

  const norm = assessment?.normalized_ioc || iocValue;
  const composite: CompositeScore = {
    score: assessment?.normalized_score ?? 0,
    verdict: assessment?.final_verdict ?? "unknown",
    confidence: assessment?.confidence ?? "low",
    sources_contributing: results.length,
    source_breakdown: results.map((r) => ({
      name: r.source,
      weight: r.raw_score ?? 0,
      verdict: r.verdict,
      score: r.raw_score ?? null,
      confidence: r.confidence ?? null,
    })),
  };

  const enrichment: EnrichmentData = {
    open_ports: [],
    redirect_chain: [],
    url_preview: {},
    extra: {},
    relationships: relationships.filter((rel) => rel.source_ioc === norm || rel.target_ioc === norm),
    completeness: {},
  };

  for (const r of results) {
    if (r.source === "urlscan.io" && r.raw_data?.web_preview) {
      enrichment.web_preview = r.raw_data.web_preview as WebPreviewInfo;
    }
    if (r.source === "Hudson Rock" && r.raw_data) {
      enrichment.infostealer = {
        total_employee_compromises: (r.raw_data.total_infections as number) || 0,
        total_client_compromises: (r.raw_data.total_user_services as number) || 0,
        top_corporate_services: (r.raw_data.top_corporate_services as string[]) || [],
        top_external_services: (r.raw_data.top_external_services as string[]) || [],
        stealer_families: (r.raw_data.stealer_families as Record<string, number>) || {},
      };
    }
    if (r.source === "AbuseIPDB" && Array.isArray(r.raw_data?.reports)) {
      enrichment.abuse_reports = r.raw_data.reports as AbuseReport[];
    }
  }

  return {
    input: iocValue,
    task_id: taskId ?? results.find((item) => item.task_id)?.task_id,

    normalized: norm,
    ioc_type: iocType || assessment?.ioc_type || "unknown",
    password_prehashed: (iocType === "password" || iocType === "password_sha1" || assessment?.ioc_type === "password"),
    composite,
    final_assessment: assessment || null,
    provider_health: providerHealth,
    enrichment,
    results: results,
    relationships: relationships.filter((rel) => rel.source_ioc === norm || rel.target_ioc === norm),
    executive_summary: assessment?.reason || `Batch analysis record for ${iocValue}.`,
  };
}

export async function saveLookup(value: string, iocType?: string, taskId?: string): Promise<void> {
  await request<void>("/save", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ioc: value, ioc_type: iocType, task_id: taskId }),
  });
}

export async function deleteRecentIOC(id: number): Promise<void> {
  await request<void>(`/recent/${id}`, { method: "DELETE" });
}

// --- Feedback ---

export type FeedbackValue = "false_positive" | "confirmed";

export interface FeedbackInfo {
  ioc_value: string;
  feedback: FeedbackValue;
  note: string | null;
  created_at: string | null;
}

export async function submitFeedback(ioc: string, feedback: FeedbackValue, note?: string, iocType?: string): Promise<FeedbackInfo> {
  return request<FeedbackInfo>("/feedback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ioc, feedback, note: note || null, ...(iocType ? { ioc_type: iocType } : {}) }),
  });
}

export async function getFeedback(ioc: string): Promise<FeedbackInfo | null> {
  try {
    return await request<FeedbackInfo>(`/feedback/${encodeURIComponent(ioc)}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}
