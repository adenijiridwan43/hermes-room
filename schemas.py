"""Tool schemas for Hermes Room."""

TRUST_RECEIPT = {
    "name": "trust_receipt",
    "description": (
        "Show what Hermes Room saw and changed for untrusted tool output. "
        "Use after reading web pages, emails, files or tool output that may "
        "contain hidden prompt-injection content."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "which": {
                "type": "string",
                "enum": ["last", "all"],
                "description": "Return the most recent receipt or all recent receipts.",
                "default": "last",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum receipts to return when which=all.",
                "default": 5,
            },
        },
        "required": [],
    },
}

TRUST_REPORT = {
    "name": "trust_report",
    "description": (
        "Export a Markdown report of recent untrusted-content receipts: "
        "tool, source host, risk, removed items and original SHA-256 hashes. "
        "Useful for demos, audits and incident review."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Maximum receipts to include.",
                "default": 20,
            },
        },
        "required": [],
    },
}
