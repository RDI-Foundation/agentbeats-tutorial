import json
import os

from dotenv import load_dotenv
import litellm

from a2a.server.tasks import TaskUpdater
from a2a.types import DataPart, Message, Part, TaskState
from a2a.utils import get_message_text, new_agent_text_message


load_dotenv()


SYSTEM_PROMPT = (
    "You are a helpful customer service agent. "
    "Follow the policy and tool instructions provided in each message."
)


class Agent:
    def __init__(self):
        self.model = os.getenv("TAU2_AGENT_LLM", "openai/gpt-4.1")
        self.messages: list[dict[str, object]] = [{"role": "system", "content": SYSTEM_PROMPT}]

    async def run(self, message: Message, updater: TaskUpdater) -> None:
        input_text = get_message_text(message)

        await updater.update_status(TaskState.working, new_agent_text_message("Thinking..."))

        self.messages.append({"role": "user", "content": input_text})

        try:
            completion = litellm.completion(
                model=self.model,
                messages=self.messages,
                temperature=0.0,
                response_format={"type": "json_object"},
            )
            assistant_content = completion.choices[0].message.content or "{}"
            assistant_json = json.loads(assistant_content)
        except Exception:
            assistant_json = {
                "name": "respond",
                "arguments": {"content": "I ran into an error processing your request."},
            }
            assistant_content = json.dumps(assistant_json)

        self.messages.append({"role": "assistant", "content": assistant_content})

        await updater.add_artifact(
            parts=[Part(root=DataPart(data=assistant_json))],
            name="Action",
        )
