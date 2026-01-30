"""
Server entry point for the Research Agent (Purple).
"""

import argparse
from a2a.server import A2AServer
from research_agent import ResearchAgent, create_agent_card

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--card-url", default=None)
    args = parser.parse_args()
    
    server = A2AServer(
        agent_card=create_agent_card(),
        executor=ResearchAgent(),
        host=args.host,
        port=args.port
    )
    
    print(f"🟣 Research Agent starting on {args.host}:{args.port}")
    server.run()

if __name__ == "__main__":
    main()