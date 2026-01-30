"""
Server entry point for the Research Agent (Purple).
"""

import argparse

import uvicorn
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore

from research_agent import ResearchAgent, create_agent_card

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--card-url", default=None)
    args = parser.parse_args()
    
    agent_card = create_agent_card(
        args.card_url or f"http://{args.host}:{args.port}/"
    )
    request_handler = DefaultRequestHandler(
        agent_executor=ResearchAgent(),
        task_store=InMemoryTaskStore(),
    )
    server = A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=request_handler,
    )
    uvicorn.run(server.build(), host=args.host, port=args.port)

if __name__ == "__main__":
    main()