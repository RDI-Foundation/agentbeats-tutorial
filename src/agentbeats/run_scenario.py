import argparse
import asyncio
import socket
import os, sys, time, subprocess, shlex, signal
from pathlib import Path
from urllib.parse import urlparse
import tomllib
import httpx
from dotenv import load_dotenv

from a2a.client import A2ACardResolver


load_dotenv(override=True)


def _endpoint_is_listening(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except OSError:
        return False


def ensure_endpoints_unused(cfg: dict) -> None:
    conflicts: list[str] = []

    for p in cfg["participants"]:
        if p.get("cmd") and _endpoint_is_listening(p["host"], p["port"]):
            conflicts.append(f"{p['role']} ({p['host']}:{p['port']})")

    if cfg["green_agent"].get("cmd") and _endpoint_is_listening(cfg["green_agent"]["host"], cfg["green_agent"]["port"]):
        conflicts.append(f"green_agent ({cfg['green_agent']['host']}:{cfg['green_agent']['port']})")

    if conflicts:
        print("Error: Some agent endpoints are already in use:")
        for conflict in conflicts:
            print(f"  - {conflict}")
        print("Pick different ports in the scenario TOML (both endpoint and cmd) or stop the process using them.")
        sys.exit(1)


async def wait_for_agents(cfg: dict, timeout: int = 30) -> bool:
    """Wait for all agents to be healthy and responding."""
    endpoints = []

    # Collect all endpoints to check
    for p in cfg["participants"]:
        if p.get("cmd"):  # Only check if there's a command (agent to start)
            endpoints.append(f"http://{p['host']}:{p['port']}")

    if cfg["green_agent"].get("cmd"):  # Only check if there's a command (host to start)
        endpoints.append(f"http://{cfg['green_agent']['host']}:{cfg['green_agent']['port']}")

    if not endpoints:
        return True  # No agents to wait for

    print(f"Waiting for {len(endpoints)} agent(s) to be ready...")
    start_time = time.time()

    async def check_endpoint(endpoint: str) -> bool:
        """Check if an endpoint is responding by fetching the agent card."""
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                resolver = A2ACardResolver(httpx_client=client, base_url=endpoint)
                await resolver.get_agent_card()
                return True
        except Exception:
            # Any exception means the agent is not ready
            return False

    while time.time() - start_time < timeout:
        ready_count = 0
        for endpoint in endpoints:
            if await check_endpoint(endpoint):
                ready_count += 1

        if ready_count == len(endpoints):
            return True

        print(f"  {ready_count}/{len(endpoints)} agents ready, waiting...")
        await asyncio.sleep(1)

    print(f"Timeout: Only {ready_count}/{len(endpoints)} agents became ready after {timeout}s")
    return False


def parse_toml(scenario_path: str) -> dict:
    path = Path(scenario_path)
    if not path.exists():
        print(f"Error: Scenario file not found: {path}")
        sys.exit(1)

    data = tomllib.loads(path.read_text())

    def parse_endpoint(ep: str) -> tuple[str, int]:
        parsed = urlparse(ep or "")
        host = parsed.hostname
        port = parsed.port
        if not host or port is None:
            print(f"Error: Invalid endpoint in scenario TOML: {ep!r}")
            sys.exit(1)
        if host in {"0.0.0.0", "::"}:
            print("Error: Endpoint host must be a connectable address (use 127.0.0.1 or ::1).")
            sys.exit(1)
        return host, port

    green_ep = data.get("green_agent", {}).get("endpoint")
    if not green_ep:
        print("Error: green_agent.endpoint is required in scenario TOML.")
        sys.exit(1)
    g_host, g_port = parse_endpoint(green_ep)
    green_cmd = data.get("green_agent", {}).get("cmd", "")

    parts = []
    for p in data.get("participants", []):
        if isinstance(p, dict) and "endpoint" in p:
            h, pt = parse_endpoint(p["endpoint"])
            parts.append({
                "role": str(p.get("role", "")),
                "host": h,
                "port": pt,
                "cmd": p.get("cmd", "")
            })

    cfg = data.get("config", {})
    return {
        "green_agent": {"host": g_host, "port": g_port, "cmd": green_cmd},
        "participants": parts,
        "config": cfg,
    }


def main():
    parser = argparse.ArgumentParser(description="Run agent scenario")
    parser.add_argument("scenario", help="Path to scenario TOML file")
    parser.add_argument("--show-logs", action="store_true",
                        help="Show agent stdout/stderr")
    parser.add_argument("--serve-only", action="store_true",
                        help="Start agent servers only without running evaluation")
    args = parser.parse_args()

    cfg = parse_toml(args.scenario)

    sink = None if args.show_logs or args.serve_only else subprocess.DEVNULL
    parent_bin = str(Path(sys.executable).parent)
    base_env = os.environ.copy()
    base_env["PATH"] = parent_bin + os.pathsep + base_env.get("PATH", "")

    procs = []
    try:
        ensure_endpoints_unused(cfg)

        # start participant agents
        for p in cfg["participants"]:
            cmd_args = shlex.split(p.get("cmd", ""))
            if cmd_args:
                print(f"Starting {p['role']} at {p['host']}:{p['port']}")
                procs.append(subprocess.Popen(
                    cmd_args,
                    env=base_env,
                    stdout=sink, stderr=sink,
                    text=True,
                    start_new_session=True,
                ))

        # start host
        green_cmd_args = shlex.split(cfg["green_agent"].get("cmd", ""))
        if green_cmd_args:
            print(f"Starting green agent at {cfg['green_agent']['host']}:{cfg['green_agent']['port']}")
            procs.append(subprocess.Popen(
                green_cmd_args,
                env=base_env,
                stdout=sink, stderr=sink,
                text=True,
                start_new_session=True,
            ))

        # Wait for all agents to be ready
        if not asyncio.run(wait_for_agents(cfg)):
            print("Error: Not all agents became ready. Exiting.")
            sys.exit(1)

        print("Agents started. Press Ctrl+C to stop.")
        if args.serve_only:
            while True:
                for proc in procs:
                    if proc.poll() is not None:
                        print(f"Agent exited with code {proc.returncode}")
                        break
                    time.sleep(0.5)
        else:
            client_proc = subprocess.Popen(
                [sys.executable, "-m", "agentbeats.client_cli", args.scenario],
                env=base_env,
                start_new_session=True,
            )
            procs.append(client_proc)
            client_proc.wait()
            if client_proc.returncode:
                sys.exit(client_proc.returncode)

    except KeyboardInterrupt:
        pass

    finally:
        print("\nShutting down...")
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        time.sleep(1)
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    main()
