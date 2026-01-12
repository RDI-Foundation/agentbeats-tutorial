import sys
import json
import asyncio
from pathlib import Path
from urllib.parse import urlparse

import tomllib

from agentbeats.client import send_message
from agentbeats.models import EvalRequest
from a2a.types import (
    AgentCard,
    Message,
    TaskStatusUpdateEvent,
    TaskArtifactUpdateEvent,
    Artifact,
    TextPart,
    DataPart,
)

def _validate_endpoint(endpoint: str) -> None:
    parsed = urlparse(endpoint)
    host = parsed.hostname
    port = parsed.port
    if not host or port is None:
        raise ValueError(f"Invalid endpoint: {endpoint!r}")
    if host in {"0.0.0.0", "::"}:
        raise ValueError("Endpoint host must be a connectable address (use 127.0.0.1 or ::1).")


def parse_toml(d: dict[str, object]) -> tuple[EvalRequest, str, dict[str, str]]:
    green = d.get("green_agent")
    if not isinstance(green, dict) or "endpoint" not in green:
        raise ValueError("green.endpoint is required in TOML")
    green_endpoint: str = green["endpoint"]
    _validate_endpoint(green_endpoint)

    parts: dict[str, str] = {}
    role_to_id: dict[str, str] = {}

    for p in d.get("participants", []):
        if isinstance(p, dict):
            role = p.get("role")
            endpoint = p.get("endpoint")
            agentbeats_id = p.get("agentbeats_id")
            if role and endpoint:
                _validate_endpoint(endpoint)
                parts[role] = endpoint
            if role and agentbeats_id:
                role_to_id[role] = agentbeats_id

    eval_req = EvalRequest(
        participants=parts,
        config=d.get("config", {}) or {}
    )
    return eval_req, green_endpoint, role_to_id

def parse_parts(parts) -> tuple[list, list]:
    text_parts = []
    data_parts = []

    for part in parts:
        if isinstance(part.root, TextPart):
            try:
                data_item = json.loads(part.root.text)
                data_parts.append(data_item)
            except Exception:
                text_parts.append(part.root.text.strip())
        elif isinstance(part.root, DataPart):
            data_parts.append(part.root.data)

    return text_parts, data_parts

def print_parts(parts, task_state: str | None = None):
    text_parts, data_parts = parse_parts(parts)

    output = []
    if task_state:
        output.append(f"[Status: {task_state}]")
    if text_parts:
        output.append("\n".join(text_parts))
    if data_parts:
        output.extend(json.dumps(item, indent=2) for item in data_parts)

    print("\n".join(output) + "\n")

async def main():
    if len(sys.argv) < 2:
        print("Usage: python client_cli.py <scenario.toml> [output.json]")
        sys.exit(1)

    scenario_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    if not scenario_path.exists():
        print(f"File not found: {scenario_path}")
        sys.exit(1)

    toml_data = scenario_path.read_text()
    data = tomllib.loads(toml_data)

    try:
        req, green_url, role_to_id = parse_toml(data)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    artifacts: list[Artifact] = []
    error_status: str | None = None

    async def event_consumer(event, card: AgentCard):
        nonlocal artifacts
        nonlocal error_status
        match event:
            case Message() as msg:
                print_parts(msg.parts)

            case (task, TaskStatusUpdateEvent() as status_event):
                status = status_event.status
                parts = status.message.parts if status.message else []
                print_parts(parts, status.state.value)
                if status.state.value == "completed":
                    print(task.artifacts)
                    artifacts = task.artifacts
                elif status.state.value not in ["submitted", "working"]:
                    error_status = status.state.value

            case (task, TaskArtifactUpdateEvent() as artifact_event):
                print_parts(artifact_event.artifact.parts, "Artifact update")

            case task, None:
                status = task.status
                parts = status.message.parts if status.message else []
                print_parts(parts, task.status.state.value)
                if status.state.value == "completed":
                    print(task.artifacts)
                    artifacts = task.artifacts
                elif status.state.value not in ["submitted", "working"]:
                    error_status = status.state.value

            case _:
                print("Unhandled event")

    msg = req.model_dump_json()
    try:
        await send_message(msg, green_url, streaming=True, consumer=event_consumer)
    finally:
        if output_path:
            all_data_parts = []
            for artifact in artifacts:
                _, data_parts = parse_parts(artifact.parts)
                all_data_parts.extend(data_parts)

            output_data = {
                "participants": role_to_id,
                "results": all_data_parts
            }

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(output_data, f, indent=2)
                print(f"Results written to {output_path}")

    if error_status:
        print(f"Agent returned status {error_status}.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
