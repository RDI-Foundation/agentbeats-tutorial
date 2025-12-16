"""
Tau2 Evaluator - Green agent that runs tau-bench evaluation on purple agents.

This agent:
1. Sets up tau-bench gymnasium environments
2. Sends task prompts to the purple agent (the agent being tested)
3. Parses the purple agent's tool-call responses
4. Steps through the environment and collects metrics
"""
import argparse
import asyncio
import json
import logging
import time
from typing import Any, Optional

import uvicorn
from dotenv import load_dotenv

load_dotenv()

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    DataPart,
    Part,
    TaskState,
    TextPart,
)
from a2a.utils import new_agent_text_message

from agentbeats.green_executor import GreenAgent, GreenExecutor
from agentbeats.models import EvalRequest
from agentbeats.tool_provider import ToolProvider

from tau2.data_model.simulation import RewardInfo
from tau2.environment.tool import Tool
from tau2.run import get_tasks

from tau2_client import Tau2Env
from tau2_models import Tau2Action

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tau2_evaluator")

RESPOND_ACTION_NAME = "respond"


def tools_to_str(tools: list[Tool]) -> str:
    """Convert tau-bench tools to JSON schema format."""
    return json.dumps([tool.openai_schema for tool in tools], indent=2)


def get_task_ids(domain: str, task_ids: Optional[list[str]], num_tasks: Optional[int] = None) -> list[str]:
    """Get task IDs for the domain, optionally limited to num_tasks."""
    task_set_name = domain
    task_split_name = "base"
    if task_ids is None:
        tasks = get_tasks(task_set_name=task_set_name, task_split_name=task_split_name)
    else:
        tasks = get_tasks(
            task_set_name=task_set_name,
            task_split_name=task_split_name,
            task_ids=task_ids,
        )

    result = [task.id for task in tasks]
    if num_tasks is not None:
        result = result[:num_tasks]
    return result


class Tau2Evaluator(GreenAgent):
    """Green agent that evaluates purple agents using tau-bench."""

    def __init__(self):
        self._required_roles = ["agent"]  # The purple agent being tested
        self._required_config_keys = ["domain"]
        self._tool_provider = ToolProvider()

    def validate_request(self, request: EvalRequest) -> tuple[bool, str]:
        missing_roles = set(self._required_roles) - set(request.participants.keys())
        if missing_roles:
            return False, f"Missing roles: {missing_roles}"
        missing_config_keys = set(self._required_config_keys) - set(request.config.keys())
        if missing_config_keys:
            return False, f"Missing config keys: {missing_config_keys}"
        return True, "ok"

    async def run_eval(self, request: EvalRequest, updater: TaskUpdater) -> None:
        logger.info(f"Starting tau2 evaluation: {request}")
        start_time = time.time()

        domain = request.config["domain"]
        task_ids = request.config.get("task_ids", None)
        num_tasks = request.config.get("num_tasks", None)
        max_steps = request.config.get("max_steps", 200)
        user_llm = request.config.get("user_llm", "openai/gpt-4o")
        user_llm_args = request.config.get("user_llm_args", {"temperature": 0.0})

        # Get the purple agent URL
        agent_url = str(request.participants["agent"])

        # Get task IDs
        resolved_task_ids = get_task_ids(domain, task_ids, num_tasks)
        logger.info(f"Running {len(resolved_task_ids)} tasks for domain {domain}")

        await updater.update_status(
            TaskState.working,
            new_agent_text_message(f"Starting evaluation of {len(resolved_task_ids)} tasks in {domain} domain")
        )

        metrics: dict[str, Any] = {"tasks": {}}

        try:
            for task_id in resolved_task_ids:
                logger.info(f"Running task {task_id}...")
                await updater.update_status(
                    TaskState.working,
                    new_agent_text_message(f"Running task {task_id}...")
                )

                try:
                    reward = await self._run_single_task(
                        agent_url=agent_url,
                        domain=domain,
                        task_id=task_id,
                        max_steps=max_steps,
                        user_llm=user_llm,
                        user_llm_args=user_llm_args,
                    )
                    metrics["tasks"][task_id] = reward
                    logger.info(f"Task {task_id} completed with reward: {reward}")
                except Exception as e:
                    logger.error(f"Task {task_id} failed: {e}")
                    metrics["tasks"][task_id] = 0.0

            time_used = time.time() - start_time
            total_reward = sum(metrics["tasks"].values())
            num_completed = len(metrics["tasks"])
            pass_rate = (total_reward / num_completed * 100) if num_completed > 0 else 0

            result_data: dict[str, Any] = {
                "domain": domain,
                "score": total_reward,
                "max_score": num_completed,
                "pass_rate": pass_rate,
                "task_rewards": metrics["tasks"],
                "time_used": time_used,
            }

            # Format task results for display
            task_results_str = "\n".join(
                f"  {task_id}: {'✓' if reward == 1.0 else '✗'} ({reward})"
                for task_id, reward in metrics["tasks"].items()
            )

            summary = f"""Tau2 Benchmark Results
Domain: {domain}
Tasks: {num_completed}
Pass Rate: {pass_rate:.1f}% ({int(total_reward)}/{num_completed})
Time: {time_used:.1f}s

Task Results:
{task_results_str}"""

            await updater.add_artifact(
                parts=[
                    Part(root=TextPart(text=summary)),
                    Part(root=DataPart(data=result_data)),
                ],
                name="Result",
            )

        finally:
            self._tool_provider.reset()

    async def _run_single_task(
        self,
        agent_url: str,
        domain: str,
        task_id: str,
        max_steps: int,
        user_llm: str,
        user_llm_args: dict[Any, Any],
    ) -> float:
        """Run a single tau-bench task and return the reward."""

        env = Tau2Env("http://localhost:8000")

        observation_sr = env.reset()

        # Build the initial task description for the purple agent
        task_description = self._build_task_prompt(env.state.info, observation_sr.observation.observation)

        # Start a new conversation with the purple agent
        next_message = task_description
        is_first_message = True

        while not observation_sr.done:
            logger.debug(f"Sending to purple agent: {next_message[:200]}...")

            # Send message to purple agent
            response: str = await self._tool_provider.talk_to_agent(
                message=next_message,
                url=agent_url,
                new_conversation=is_first_message,
            )
            is_first_message = False

            logger.debug(f"Purple agent response: {response[:200]}...")

            # Parse the purple agent's action
            try:
                action = Tau2Action(action=self._parse_agent_response(response))
            except Exception as e:
                logger.error(f"Failed to parse agent response: {e}")
                # When parsing fails, respond with error as plain text (not a tool call)
                action = Tau2Action(action="I encountered an error processing the request.")

            # Step the environment with either a JSON string (tool call) or plain text (user response)
            observation_sr = env.step(action)
            logger.debug(f"Environment step: reward={observation_sr.reward}, done={observation_sr.done}")

            if observation_sr.done:
                break

            next_message = observation_sr.observation.observation

        # Extract final reward
        if env.state.info.get("reward_info"):
            reward_info = RewardInfo.model_validate_json(env.state.info["reward_info"])
            return reward_info.reward
        return 0. if observation_sr.reward is None else float(observation_sr.reward)

    def _build_task_prompt(self, info: dict[Any, Any], observation: str) -> str:
        """Build the initial task prompt for the purple agent."""
        return f"""
{info["policy"]}

Here's a list of tools you can use (you can use at most one tool at a time):
{tools_to_str(info["tools"])}

Please respond in JSON format. Wrap the JSON with <json>...</json> tags.
The JSON should contain:
- "name": the tool call function name, or "{RESPOND_ACTION_NAME}" if you want to respond directly.
- "arguments": the arguments for the tool call, or {{"content": "your message here"}} if you want to respond directly.

You should only use one tool at a time!
You cannot respond to user and use a tool at the same time!

Examples of responses:
<json>
{json.dumps({"name": "find_user_id_by_name_zip", "arguments": {"first_name": "Yusuf", "last_name": "Rossi", "zip_code": "19122"}}, indent=2)}
</json>

<json>
{json.dumps({"name": RESPOND_ACTION_NAME, "arguments": {"content": "Hello, how can I help you today?"}}, indent=2)}
</json>

Now here is the user message:
{observation}
"""

    def _parse_agent_response(self, response: str) -> str:
        """Parse the purple agent's response to extract the action."""
        import re

        json_str = None

        # Try to extract JSON from <json>...</json> tags
        match = re.search(r'<json>\s*(.*?)\s*</json>', response, re.DOTALL)
        if match:
            json_str = match.group(1)
        else:
            # Try to extract JSON from markdown code blocks ```json ... ```
            match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
            if match:
                json_str = match.group(1)
            else:
                # Try to extract from generic code blocks ``` ... ```
                match = re.search(r'```\s*(.*?)\s*```', response, re.DOTALL)
                if match:
                    json_str = match.group(1)

        if json_str:
            action_dict = json.loads(json_str)
        else:
            # Try to parse the entire response as JSON
            action_dict = json.loads(response)

        is_tool_call = action_dict["name"] != RESPOND_ACTION_NAME
        if not is_tool_call:
            return action_dict["arguments"]["content"]
        else:
            return json.dumps(action_dict)


def tau2_evaluator_agent_card(name: str, url: str) -> AgentCard:
    """Create the agent card for the tau2 evaluator."""
    skill = AgentSkill(
        id="tau2_evaluation",
        name="Tau2 Benchmark Evaluation",
        description="Evaluates agents on tau-bench tasks (airline, retail domains)",
        tags=["benchmark", "evaluation", "tau2"],
        examples=[
            '{"participants": {"agent": "http://localhost:9019"}, "config": {"domain": "airline", "num_tasks": 5}}'
        ],
    )
    return AgentCard(
        name=name,
        description="Tau2 benchmark evaluator - tests agents on customer service tasks",
        url=url,
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[skill],
    )


async def main():
    parser = argparse.ArgumentParser(description="Run the tau2 evaluator agent.")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind the server")
    parser.add_argument("--port", type=int, default=9009, help="Port to bind the server")
    parser.add_argument("--card-url", type=str, help="External URL for the agent card")
    args = parser.parse_args()

    agent_url = args.card_url or f"http://{args.host}:{args.port}/"

    agent = Tau2Evaluator()
    executor = GreenExecutor(agent)
    agent_card = tau2_evaluator_agent_card("Tau2Evaluator", agent_url)

    request_handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=InMemoryTaskStore(),
    )

    server = A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=request_handler,
    )

    uvicorn_config = uvicorn.Config(server.build(), host=args.host, port=args.port)
    uvicorn_server = uvicorn.Server(uvicorn_config)
    await uvicorn_server.serve()


if __name__ == "__main__":
    asyncio.run(main())
