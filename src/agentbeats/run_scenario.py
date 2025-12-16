import argparse
import asyncio
import os, sys, time, subprocess, shlex, signal
from pathlib import Path
import tomllib
import httpx
from dotenv import find_dotenv, load_dotenv

from a2a.client import A2ACardResolver


dotenv_path = find_dotenv()
if dotenv_path:
    load_dotenv(dotenv_path, override=True)


async def wait_for_environments(cfg: dict, timeout: int = 30) -> bool:
    """Wait for all environments to be healthy and responding."""
    endpoints = []

    # Collect environment endpoints to check
    for e in cfg.get("environments", []):
        if e.get("image"):  # Only check if there's an image (container to start)
            endpoints.append(f"http://{e['host']}:{e['port']}")

    if not endpoints:
        return True  # No environments to wait for

    print(f"Waiting for {len(endpoints)} environment(s) to be ready...")
    start_time = time.time()

    async def check_endpoint(endpoint: str) -> bool:
        """Check if an environment server is responding via /health endpoint."""
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                response = await client.get(f"{endpoint}/health")
                return response.status_code == 200
        except Exception:
            return False

    while time.time() - start_time < timeout:
        ready_count = 0
        for endpoint in endpoints:
            if await check_endpoint(endpoint):
                ready_count += 1

        if ready_count == len(endpoints):
            return True

        print(f"  {ready_count}/{len(endpoints)} environments ready, waiting...")
        await asyncio.sleep(1)

    print(f"Timeout: Only {ready_count}/{len(endpoints)} environments became ready after {timeout}s")
    return False


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

    def host_port(ep: str):
        s = (ep or "")
        s = s.replace("http://", "").replace("https://", "")
        s = s.split("/", 1)[0]
        host, port = s.split(":", 1)
        return host, int(port)

    green_ep = data.get("green_agent", {}).get("endpoint", "")
    g_host, g_port = host_port(green_ep)
    green_cmd = data.get("green_agent", {}).get("cmd", "")

    parts = []
    for p in data.get("participants", []):
        if isinstance(p, dict) and "endpoint" in p:
            h, pt = host_port(p["endpoint"])
            parts.append({
                "role": str(p.get("role", "")),
                "host": h,
                "port": pt,
                "cmd": p.get("cmd", "")
            })

    envs = []
    for e in data.get("environments", []):
        if isinstance(e, dict) and "endpoint" in e:
            h, pt = host_port(e["endpoint"])
            envs.append({
                "name": str(e.get("name", "")),
                "host": h,
                "port": pt,
                "image": e.get("image", ""),
                "publishes": e.get("publishes", []),
                "env": e.get("env", {}),
            })

    cfg = data.get("config", {})
    return {
        "environments": envs,
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
    containers = []
    try:
        # start environments
        for e in cfg.get("environments", []):
            if e.get("image", ""):
                container_name = f"agentbeats-{e['name']}-{int(time.time())}"
                cmd_args = [
                    "docker", "run",
                    "--rm",
                    "--name", container_name,
                ]
                for publish in e["publishes"]:
                    cmd_args.extend(["-p", publish])
                if dotenv_path:
                    cmd_args.extend(["--env-file", dotenv_path])
                for key, value in e["env"].items():
                    cmd_args.extend(["-e", f"{key}={value}"])
                cmd_args.append(e["image"])
                print(f"Starting environment {e['name']} at {e['host']}:{e['port']} (container: {container_name})")
                procs.append(subprocess.Popen(
                    cmd_args,
                    stdout=sink, stderr=sink,
                    text=True,
                    start_new_session=True,
                ))
                containers.append(container_name)

        # Wait for all environments to be ready
        if not asyncio.run(wait_for_environments(cfg)):
            print("Error: Not all environments became ready. Exiting.")
            return

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
            return

        print("Agents started. Press Ctrl+C to stop.")
        if args.serve_only:
            while True:
                for proc in procs:
                    if proc.poll() is not None:
                        print(f"Process exited with code {proc.returncode}")
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

    except KeyboardInterrupt:
        pass

    finally:
        print("\nShutting down...")
        for c in containers:
            try:
                subprocess.run(
                    ["docker", "stop", c],
                    stdout=sink, stderr=sink,
                )
            except Exception as e:
                print(f"Error in docker stop {c}: {e}")
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
