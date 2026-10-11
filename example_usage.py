"""Example usage for Remote MCP OAuth Scope Auditor."""
from client import MCPOAuthScopeAuditor

if __name__ == "__main__":
    report = MCPOAuthScopeAuditor.audit_oauth_grant(
        "remote-postgres-mcp",
        ["db:read", "schema:inspect", "db:drop"],
        read_only_mode=True
    )
    print("Verdict:", report["verdict"])
    print("Violations:", report["violations"])
