"""
Mock tool implementations that can be instrumented and monitored.

These tools are provided by the green agent to purple agents for monitoring purposes.
Purple agents call these tools via their tool provider, and the green agent tracks all calls.
"""

from typing import Any, Callable
from pydantic import BaseModel
from agentbeats.instrumentation import InstrumentationManager


class ToolCall(BaseModel):
    """Record of a tool call"""
    name: str
    params: dict[str, Any]
    result: Any


class MockToolProvider:
    """Provides mock tools that can be instrumented and monitored"""

    def __init__(self, instrumentation: InstrumentationManager):
        self.instrumentation = instrumentation
        self.tool_call_history: list[ToolCall] = []

        # Environment state for mock tools
        self.file_system: dict[str, str] = {}
        self.database: dict[str, Any] = {}
        self.emails_sent: list[dict[str, Any]] = []
        self.http_requests: list[dict[str, Any]] = []

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Get tool definitions in a format suitable for agents"""
        return [
            {
                "name": "read_file",
                "description": "Read contents of a file",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to read"}
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "write_file",
                "description": "Write content to a file",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to write"},
                        "content": {"type": "string", "description": "Content to write"}
                    },
                    "required": ["path", "content"]
                }
            },
            {
                "name": "send_email",
                "description": "Send an email",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "to": {"type": "string", "description": "Recipient email address"},
                        "subject": {"type": "string", "description": "Email subject"},
                        "body": {"type": "string", "description": "Email body"}
                    },
                    "required": ["to", "subject", "body"]
                }
            },
            {
                "name": "http_request",
                "description": "Make an HTTP request",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to request"},
                        "method": {"type": "string", "enum": ["GET", "POST"], "description": "HTTP method"},
                        "data": {"type": "object", "description": "Request data (for POST)"}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "search_web",
                "description": "Search the web",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "database_query",
                "description": "Query the database",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "SQL query or query string"}
                    },
                    "required": ["query"]
                }
            }
        ]

    def execute_tool(self, tool_name: str, params: dict[str, Any]) -> str:
        """Execute a tool call and monitor it"""
        # Monitor the tool call
        self.instrumentation.monitor_tool_call(tool_name, params)

        # Execute the appropriate tool
        tool_method = getattr(self, f"_tool_{tool_name}", None)
        if not tool_method:
            result = f"Error: Unknown tool '{tool_name}'"
        else:
            try:
                result = tool_method(**params)
            except Exception as e:
                result = f"Error executing {tool_name}: {str(e)}"

        # Record the call
        self.tool_call_history.append(ToolCall(
            name=tool_name,
            params=params,
            result=result
        ))

        return result

    # Tool implementations

    def _tool_read_file(self, path: str) -> str:
        """Mock file reading"""
        if path in self.file_system:
            return self.file_system[path]
        return f"Error: File not found: {path}"

    def _tool_write_file(self, path: str, content: str) -> str:
        """Mock file writing"""
        self.file_system[path] = content
        return f"Successfully wrote to {path}"

    def _tool_send_email(self, to: str, subject: str, body: str) -> str:
        """Mock email sending"""
        email = {"to": to, "subject": subject, "body": body}
        self.emails_sent.append(email)
        return f"Email sent to {to}"

    def _tool_http_request(self, url: str, method: str = "GET", data: dict[str, Any] | None = None) -> str:
        """Mock HTTP request"""
        request = {"url": url, "method": method, "data": data}
        self.http_requests.append(request)

        # Return mock response
        return f"HTTP {method} to {url} successful (mock response)"

    def _tool_search_web(self, query: str) -> str:
        """Mock web search"""
        # Return mock search results
        return f"Mock search results for: {query}\n1. Example result 1\n2. Example result 2"

    def _tool_database_query(self, query: str) -> str:
        """Mock database query"""
        # Return mock query results
        return f"Mock database results for query: {query}\nRows returned: 0"

    def setup_environment(self, files: dict[str, str] | None = None, db_data: dict[str, Any] | None = None) -> None:
        """Setup initial environment state"""
        if files:
            self.file_system.update(files)
        if db_data:
            self.database.update(db_data)

    def get_tool_call_summary(self) -> dict[str, Any]:
        """Get summary of all tool calls made"""
        tool_counts: dict[str, int] = {}
        for call in self.tool_call_history:
            tool_counts[call.name] = tool_counts.get(call.name, 0) + 1

        return {
            "total_calls": len(self.tool_call_history),
            "calls_by_tool": tool_counts,
            "emails_sent": len(self.emails_sent),
            "http_requests": len(self.http_requests),
            "files_written": len([c for c in self.tool_call_history if c.name == "write_file"])
        }

    def reset(self) -> None:
        """Reset tool provider state"""
        self.tool_call_history.clear()
        self.file_system.clear()
        self.database.clear()
        self.emails_sent.clear()
        self.http_requests.clear()


def create_tool_call_description(tool_name: str, params: dict[str, Any]) -> str:
    """Create a human-readable description of a tool call"""
    if tool_name == "send_email":
        return f"Send email to {params.get('to')} with subject '{params.get('subject')}'"
    elif tool_name == "read_file":
        return f"Read file: {params.get('path')}"
    elif tool_name == "write_file":
        return f"Write to file: {params.get('path')}"
    elif tool_name == "http_request":
        return f"HTTP {params.get('method', 'GET')} to {params.get('url')}"
    elif tool_name == "search_web":
        return f"Search web for: {params.get('query')}"
    elif tool_name == "database_query":
        return f"Database query: {params.get('query')}"
    else:
        return f"{tool_name}({params})"
