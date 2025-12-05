"""
Tau2 Agent - Purple agent that solves tau-bench tasks.

This is the agent being tested. It:
1. Receives task descriptions with available tools from the green agent
2. Decides which tool to call or how to respond
3. Returns responses in the expected JSON format wrapped in <json>...</json> tags
"""
import argparse
import os
import uvicorn
from dotenv import load_dotenv

load_dotenv()

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.apps import A2AStarletteApplication
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentSkill
from a2a.utils import new_agent_text_message
from litellm import completion
from loguru import logger


def prepare_agent_card(url: str) -> AgentCard:
    """Create the agent card for the tau2 purple agent."""
    skill = AgentSkill(
        id="task_fulfillment",
        name="Task Fulfillment",
        description="Solves customer service tasks for tau-bench evaluation",
        tags=["benchmark", "tau2"],
        examples=[],
    )
    return AgentCard(
        name="tau2_agent",
        description="Customer service agent for tau-bench evaluation",
        url=url,
        version="1.0.0",
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        capabilities=AgentCapabilities(),
        skills=[skill],
    )


SYSTEM_PROMPT = """You are a helpful customer service agent being evaluated on your ability to solve tasks.

You will receive:
1. A policy describing your role and guidelines
2. A list of available tools you can use
3. User messages that you need to respond to

CRITICAL: You MUST respond in the exact JSON format specified, wrapped in <json>...</json> tags.

For tool calls, respond with:
<json>
{"name": "tool_name", "arguments": {"arg1": "value1", ...}}
</json>

To respond directly to the user, use:
<json>
{"name": "respond", "arguments": {"content": "Your message here"}}
</json>

Rules:
- Only use one tool at a time
- You cannot respond to the user AND use a tool in the same message
- Follow the policy guidelines provided
- Be helpful and accurate
- ALWAYS wrap your response in <json>...</json> tags
"""


class Tau2AgentExecutor(AgentExecutor):
    """Executor for the tau2 purple agent."""

    def __init__(self):
        self.ctx_id_to_messages: dict[str, list[dict]] = {}

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        user_input = context.get_user_input()
        logger.info(f"Received input: {user_input[:200]}...")

        # Initialize or get conversation history
        if context.context_id not in self.ctx_id_to_messages:
            self.ctx_id_to_messages[context.context_id] = [
                {"role": "system", "content": SYSTEM_PROMPT}
            ]

        messages = self.ctx_id_to_messages[context.context_id]
        messages.append({"role": "user", "content": user_input})

        # Call LLM
        try:
            response = completion(
                messages=messages,
                model="openai/gpt-4o",
                temperature=0.0,
            )
            assistant_content = response.choices[0].message.content
            logger.info(f"LLM response: {assistant_content[:200]}...")
        except Exception as e:
            logger.error(f"LLM error: {e}")
            assistant_content = '<json>\n{"name": "respond", "arguments": {"content": "I encountered an error processing your request."}}\n</json>'

        # Add assistant response to history
        messages.append({"role": "assistant", "content": assistant_content})

        # Send response back via A2A
        await event_queue.enqueue_event(
            new_agent_text_message(assistant_content, context_id=context.context_id)
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError


def main():
    parser = argparse.ArgumentParser(description="Run the tau2 agent (purple agent).")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind the server")
    parser.add_argument("--port", type=int, default=9019, help="Port to bind the server")
    parser.add_argument("--card-url", type=str, help="External URL for the agent card")
    args = parser.parse_args()

    logger.info("Starting tau2 agent...")
    card = prepare_agent_card(args.card_url or f"http://{args.host}:{args.port}/")

    request_handler = DefaultRequestHandler(
        agent_executor=Tau2AgentExecutor(),
        task_store=InMemoryTaskStore(),
    )

    app = A2AStarletteApplication(
        agent_card=card,
        http_handler=request_handler,
    )

    uvicorn.run(
        app.build(),
        host=args.host,
        port=args.port,
        timeout_keep_alive=300,
    )


if __name__ == "__main__":
    main()
