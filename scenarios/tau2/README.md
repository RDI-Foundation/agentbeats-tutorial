# Tau2 Benchmark Scenario

This scenario evaluates agents on the [tau2-bench](https://github.com/sierra-research/tau2-bench) benchmark, which tests customer service agents on realistic tasks.

## Setup

1. **Install tau2 dependencies**:

   ```bash
   uv sync --extra tau2-agent --extra tau2-evaluator
   ```

2. **Download the tau2-bench data** (required once):

   ```bash
   ./scenarios/tau2/setup.sh
   ```

3. **Set your API key** in `.env`:

   ```
   OPENAI_API_KEY=your-key-here
   ```

## Running the Benchmark

```bash
uv run agentbeats-run scenarios/tau2/scenario.toml
```

By default the evaluator uses `./scenarios/tau2/tau2-bench/data` if it exists. Set `TAU2_DATA_DIR` to override.

If you see `Error: Some agent endpoints are already in use`, update the `endpoint` + `--port` values in `scenarios/tau2/scenario.toml`.

## Configuration

Edit `scenario.toml` to configure the benchmark:

```toml
[config]
domain = "airline"      # airline, retail, telecom, or mock
num_tasks = 5           # number of tasks to run
user_llm = "openai/gpt-4.1"  # LLM for user simulator (optional, defaults to gpt-4.1)
```

The agent LLM defaults to `openai/gpt-4.1` and can be configured via the `--agent-llm` CLI argument in `scenarios/tau2/agent/src/server.py`.

## Architecture

- **evaluator/src/** (Green Agent): Runs the tau2 Orchestrator which coordinates the user simulator, environment, and agent
- **agent/src/** (Purple Agent): The agent being tested - receives task descriptions and responds with tool calls or user responses
