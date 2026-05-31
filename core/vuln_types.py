"""
Normalized vulnerability category codes.

Every module finding dict must include a ``"category"`` key set to one of
these constants.  ``classify_severity()`` in scanner.py does an O(1) exact
dict lookup on this value — no substring or regex matching at all.

Rule: the *category* identifies the vulnerability class; the *type* string
in the finding dict is the human-readable title shown in reports.
"""


class VT:
    # ── Injection ────────────────────────────────────────────────────────────
    SQL_INJECTION           = "sql_injection"
    NOSQL_INJECTION         = "nosql_injection"
    SSTI                    = "ssti"
    COMMAND_INJECTION       = "command_injection"
    RCE                     = "rce"
    DESERIALIZATION         = "deserialization"
    LFI                     = "lfi"
    RFI                     = "rfi"
    PROTOTYPE_POLLUTION     = "prototype_pollution"
    # ── XSS ──────────────────────────────────────────────────────────────────
    XSS_STORED              = "xss_stored"
    XSS                     = "xss"
    # ── Other injection / request forgery ────────────────────────────────────
    XXE                     = "xxe"
    SSRF                    = "ssrf"
    CSRF                    = "csrf"
    # ── Authentication ────────────────────────────────────────────────────────
    JWT_WEAK                = "jwt_weak"
    DEFAULT_CREDS           = "default_creds"
    WEAK_PASSWORD_RESET     = "weak_password_reset"
    MASS_ASSIGNMENT         = "mass_assignment"
    AUTH_STATE_EXPOSURE     = "auth_state_exposure"
    BROKEN_AUTH             = "broken_auth"
    # ── Access control ────────────────────────────────────────────────────────
    BROKEN_ACCESS_CONTROL   = "broken_access_control"
    IDOR                    = "idor"
    HTTP_METHOD_OVERRIDE    = "http_method_override"
    PARAMETER_POLLUTION     = "parameter_pollution"
    # ── Misconfiguration ──────────────────────────────────────────────────────
    MISSING_SECURITY_HEADER = "missing_security_header"
    CORS_CREDENTIALED       = "cors_credentialed"
    CORS_WILDCARD           = "cors_wildcard"
    CSP_MISCONFIG           = "csp_misconfig"
    INSECURE_COOKIE         = "insecure_cookie"
    CLICKJACKING            = "clickjacking"
    RATE_LIMITING           = "rate_limiting"
    DANGEROUS_HTTP_METHOD   = "dangerous_http_method"
    HTTP_TRACE              = "http_trace"
    SECURITY_MISCONFIG      = "security_misconfig"
    VULNERABLE_COMPONENT    = "vulnerable_component"
    COMPONENT_VERSION_DISC  = "component_version_disclosure"
    DEBUG_ENDPOINT          = "debug_endpoint"
    # ── Sensitive data ────────────────────────────────────────────────────────
    SENSITIVE_FILE          = "sensitive_file"
    CRYPTO_KEY_EXPOSURE     = "crypto_key_exposure"
    PASSWORD_HASH_LEAK      = "password_hash_leak"
    SENSITIVE_DATA_API      = "sensitive_data_api"
    SENSITIVE_DATA_JS       = "sensitive_data_js"
    LEAKED_API_KEY          = "leaked_api_key"
    CRYPTO_ISSUE_WEAK_HASH  = "crypto_issue_weak_hash"
    CRYPTO_ISSUE            = "crypto_issue"
    # ── Disclosure ────────────────────────────────────────────────────────────
    INFO_DISCLOSURE         = "info_disclosure"
    INFO_DISCLOSURE_STACK   = "info_disclosure_stack"
    # ── Misc ─────────────────────────────────────────────────────────────────
    OPEN_REDIRECT           = "open_redirect"
    HOST_HEADER             = "host_header"
    GRAPHQL                 = "graphql"
