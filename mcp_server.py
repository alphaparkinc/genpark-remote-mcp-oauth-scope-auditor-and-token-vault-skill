"""MCP server for Remote MCP OAuth Scope Auditor."""
import sys
import json
from client import MCPOAuthScopeAuditor

def handle_request(req):
    method = req.get("method")
    if method == "tools/list":
        return {
            "tools": [{
                "name": "audit_mcp_oauth_scopes",
                "description": "Audits OAuth scopes requested by remote MCP servers for least-privilege compliance",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server_id": {"type": "string"},
                        "requested_scopes": {"type": "array"},
                        "read_only_mode": {"type": "boolean"}
                    },
                    "required": ["server_id", "requested_scopes"]
                }
            }]
        }
    elif method == "tools/call":
        params = req.get("params", {})
        if params.get("name") == "audit_mcp_oauth_scopes":
            args = params.get("arguments", {})
            res = MCPOAuthScopeAuditor.audit_oauth_grant(
                args.get("server_id", "unknown"),
                args.get("requested_scopes", []),
                args.get("read_only_mode", True)
            )
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
    return {"error": "Method not found"}

if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle_request(json.loads(line))))
            sys.stdout.flush()
