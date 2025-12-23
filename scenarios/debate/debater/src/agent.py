from dotenv import load_dotenv
from google import genai

from a2a.server.tasks import TaskUpdater
from a2a.types import Message, Part, TaskState, TextPart
from a2a.utils import get_message_text, new_agent_text_message


load_dotenv()


SYSTEM_PROMPT = """
You are a professional debater.
Follow the role instructions in the prompt (Pro/Affirmative or Con/Negative).
Write a persuasive, well-structured argument. Keep it concise (<= 200 words).
"""


class Agent:
    def __init__(self):
        self.client = genai.Client()

    async def run(self, message: Message, updater: TaskUpdater) -> None:
        prompt = get_message_text(message)

        await updater.update_status(TaskState.working, new_agent_text_message("Thinking..."))

        response = self.client.models.generate_content(
            model="gemini-2.5-flash-lite",
            config=genai.types.GenerateContentConfig(system_instruction=SYSTEM_PROMPT),
            contents=prompt,
        )
        text = response.text or ""

        await updater.add_artifact(
            parts=[Part(root=TextPart(text=text))],
            name="Response",
        )

