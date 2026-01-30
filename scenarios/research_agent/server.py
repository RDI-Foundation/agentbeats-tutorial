"""
Server entry point for the Research Evaluator Green Agent.
"""

import argparse
from a2a.server import A2AServer
from research_evaluator import ResearchEvaluator, create_agent_card

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--card-url", default=None)
    args = parser.parse_args()
    
    # Create the server with our evaluator
    server = A2AServer(
        agent_card=create_agent_card(),
        executor=ResearchEvaluator(),
        host=args.host,
        port=args.port
    )
    
    print(f"🟢 Research Evaluator starting on {args.host}:{args.port}")
    server.run()

if __name__ == "__main__":
    main()