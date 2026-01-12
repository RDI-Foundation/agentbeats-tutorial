import argparse
import os
from pathlib import Path

from dotenv import load_dotenv
import uvicorn
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
)


def _default_tau2_data_dir() -> Path:
    tau2_dir = Path(__file__).resolve().parents[2]
    return tau2_dir / "tau2-bench" / "data"


def _ensure_tau2_data_dir() -> None:
    if os.environ.get("TAU2_DATA_DIR"):
        return

    default_dir = _default_tau2_data_dir()
    if default_dir.exists():
        os.environ["TAU2_DATA_DIR"] = str(default_dir)
        print(f"TAU2_DATA_DIR not set; defaulting to {default_dir}")



def main():
    load_dotenv()
    _ensure_tau2_data_dir()

    from executor import Executor

    parser = argparse.ArgumentParser(description="Run the tau2 evaluator (green agent).")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind the server")
    parser.add_argument("--port", type=int, default=9009, help="Port to bind the server")
    parser.add_argument("--card-url", type=str, help="URL to advertise in the agent card")
    args = parser.parse_args()

    skill = AgentSkill(
        id="tau2_evaluation",
        name="Tau2 Benchmark Evaluation",
        description="Evaluates agents on tau-bench tasks (airline, retail, etc).",
        tags=["benchmark", "evaluation", "tau2"],
        examples=[
            '{"participants": {"agent": "http://localhost:9019"}, "config": {"domain": "airline", "num_tasks": 5}}'
        ],
    )

    agent_card = AgentCard(
        name="Tau2 Evaluator",
        description="Tau2 benchmark evaluator - tests agents on customer service tasks.",
        url=args.card_url or f"http://{args.host}:{args.port}/",
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[skill],
    )

    request_handler = DefaultRequestHandler(
        agent_executor=Executor(),
        task_store=InMemoryTaskStore(),
    )
    server = A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=request_handler,
    )
    uvicorn.run(server.build(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
