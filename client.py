"""Remote MCP OAuth Scope Auditor & Token Vault.
100% Python Standard Library.
"""

class MCPOAuthScopeAuditor:
    """Audits OAuth 2.1 scopes requested by remote MCP servers against least-privilege policies."""

    HIGH_RISK_SCOPES = {
        "admin:org": "Full organization admin control",
        "delete_repo": "Ability to permanently delete repositories",
        "db:drop": "Destructive database schema deletion",
        "billing:write": "Modify payment methods and billing plans",
        "root:*": "Unrestricted root wildcard access"
    }

    @classmethod
    def audit_oauth_grant(cls, server_id: str, requested_scopes: list, read_only_mode: bool = True) -> dict:
        violations = []
        approved_scopes = []

        for scope in requested_scopes:
            if scope in cls.HIGH_RISK_SCOPES:
                violations.append({
                    "scope": scope,
                    "risk": "CRITICAL",
                    "reason": cls.HIGH_RISK_SCOPES[scope]
                })
            elif read_only_mode and any(w in scope.lower() for w in ["write", "delete", "admin", "update", "manage"]):
                violations.append({
                    "scope": scope,
                    "risk": "HIGH",
                    "reason": "Write/mutation scope requested while read_only_mode is enforced"
                })
            else:
                approved_scopes.append(scope)

        verdict = "REJECTED" if violations else "APPROVED"
        return {
            "server_id": server_id,
            "verdict": verdict,
            "approved_scopes": approved_scopes,
            "violations_count": len(violations),
            "violations": violations
        }
