# Tau2 Benchmark Scenario

This scenario evaluates agents on the [tau2-bench](https://github.com/sierra-research/tau2-bench) benchmark, which tests customer service agents on realistic tasks.

## Setup

1. **Download the tau2-bench data** (required once):

   ```bash
   ./scenarios/tau2/setup.sh
   ```

2. **Set your API key** in `.env`:

   ```
   OPENAI_API_KEY=your-key-here
   ```

## Running the Benchmark

```bash
TAU2_DATA_DIR=./scenarios/tau2/tau2-bench/data uv run agentbeats-run scenarios/tau2/scenario.toml
```

If you see `Error: Some agent endpoints are already in use`, update the `endpoint` + `--port` values in `scenarios/tau2/scenario.toml`.

## Configuration

Edit `scenario.toml` to configure the benchmark:

```toml
[config]
domain = "airline"      # airline, retail, telecom, or mock
num_tasks = 5           # number of tasks to run
user_llm = "openai/gpt-4.1"  # LLM for user simulator (optional, defaults to gpt-4.1)
```

The agent LLM defaults to `openai/gpt-4.1` and can be configured via the `--agent-llm` CLI argument in `tau2_agent.py`.

## Architecture

- **tau2_evaluator.py** (Green Agent): Runs the tau2 Orchestrator which coordinates the user simulator, environment, and agent
- **tau2_agent.py** (Purple Agent): The agent being tested - receives task descriptions and responds with tool calls or user responses
