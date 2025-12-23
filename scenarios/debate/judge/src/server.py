import argparse

import uvicorn
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
)

from executor import Executor


def main():
    parser = argparse.ArgumentParser(description="Run the debate judge (green agent).")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind the server")
    parser.add_argument("--port", type=int, default=9009, help="Port to bind the server")
    parser.add_argument("--card-url", type=str, help="URL to advertise in the agent card")
    args = parser.parse_args()

    skill = AgentSkill(
        id="moderate_and_judge_debate",
        name="Orchestrates and judges debate",
        description="Orchestrates and judges a debate between two agents on a given topic.",
        tags=["debate"],
        examples=[
            """
{
  "participants": {
    "pro_debater": "https://pro-debater.example.com:443",
    "con_debater": "https://con-debater.example.org:8443"
  },
  "config": {
    "topic": "Should artificial intelligence be regulated?",
    "num_rounds": 3
  }
}
""".strip()
        ],
    )

    agent_card = AgentCard(
        name="Debate Judge",
        description="Orchestrates and judges a structured debate between pro and con agents on a topic.",
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

