import logging
from typing import Any, Literal

from dotenv import load_dotenv
from google import genai
from pydantic import BaseModel, HttpUrl, ValidationError

from a2a.server.tasks import TaskUpdater
from a2a.types import DataPart, Message, Part, TaskState, TextPart
from a2a.utils import get_message_text, new_agent_text_message

from messenger import Messenger


load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("debate_judge")


class EvalRequest(BaseModel):
    participants: dict[str, HttpUrl]
    config: dict[str, Any]


class DebaterScore(BaseModel):
    emotional_appeal: float
    argument_clarity: float
    argument_arrangement: float
    relevance_to_topic: float
    total_score: float


class DebateEval(BaseModel):
    pro_debater: DebaterScore
    con_debater: DebaterScore
    winner: Literal["pro_debater", "con_debater"]
    reason: str


class Agent:
    required_roles: list[str] = ["pro_debater", "con_debater"]
    required_config_keys: list[str] = ["topic", "num_rounds"]

    def __init__(self):
        self.messenger = Messenger()
        self.client = genai.Client()

    def validate_request(self, request: EvalRequest) -> tuple[bool, str]:
        missing_roles = set(self.required_roles) - set(request.participants.keys())
        if missing_roles:
            return False, f"Missing roles: {missing_roles}"

        missing_config_keys = set(self.required_config_keys) - set(request.config.keys())
        if missing_config_keys:
            return False, f"Missing config keys: {missing_config_keys}"

        try:
            int(request.config["num_rounds"])
        except Exception as e:
            return False, f"Can't parse num_rounds: {e}"

        return True, "ok"

    async def run(self, message: Message, updater: TaskUpdater) -> None:
        input_text = get_message_text(message)

        try:
            request = EvalRequest.model_validate_json(input_text)
            ok, validation_msg = self.validate_request(request)
            if not ok:
                await updater.reject(new_agent_text_message(validation_msg))
                return
        except ValidationError as e:
            await updater.reject(new_agent_text_message(f"Invalid request: {e}"))
            return

        await updater.update_status(
            TaskState.working,
            new_agent_text_message(f"Starting assessment.\n{request.model_dump_json()}"),
        )

        try:
            debate = await self.orchestrate_debate(
                request.participants,
                topic=str(request.config["topic"]),
                num_rounds=int(request.config["num_rounds"]),
                updater=updater,
            )

            debate_text = ""
            for i, (pro, con) in enumerate(
                zip(debate["pro_debater"], debate["con_debater"]), start=1
            ):
                debate_text += f"Pro Argument {i}: {pro}\n"
                debate_text += f"Con Argument {i}: {con}\n"

            await updater.update_status(
                TaskState.working,
                new_agent_text_message("Debate finished. Starting evaluation."),
            )
            logger.info("Debate finished. Evaluating.")

            debate_eval = await self.judge_debate(str(request.config["topic"]), debate_text)

            await updater.add_artifact(
                parts=[
                    Part(root=TextPart(text=debate_eval.reason)),
                    Part(root=DataPart(data=debate_eval.model_dump())),
                ],
                name="Result",
            )
        finally:
            self.messenger.reset()

    async def orchestrate_debate(
        self,
        participants: dict[str, str],
        topic: str,
        num_rounds: int,
        updater: TaskUpdater,
    ) -> dict[str, list[str]]:
        debate: dict[str, list[str]] = {"pro_debater": [], "con_debater": []}

        async def turn(role: str, prompt: str) -> str:
            response = await self.messenger.talk_to_agent(prompt, str(participants[role]))
            logger.info(f"{role}: {response}")
            debate[role].append(response)
            await updater.update_status(
                TaskState.working, new_agent_text_message(f"{role}: {response}")
            )
            return response

        pro_instructions = "You are the Pro (Affirmative) side. Argue in favor of the proposition."
        con_instructions = "You are the Con (Negative) side. Argue against the proposition."

        response = await turn(
            "pro_debater",
            f"{pro_instructions}\nDebate topic: {topic}\nPresent your opening argument.",
        )
        response = await turn(
            "con_debater",
            f"{con_instructions}\nDebate topic: {topic}\nYour opponent opened with: {response}\nPresent your opening argument.",
        )

        for _ in range(num_rounds - 1):
            response = await turn(
                "pro_debater",
                f"{pro_instructions}\nYour opponent said: {response}\nPresent your next argument.",
            )
            response = await turn(
                "con_debater",
                f"{con_instructions}\nYour opponent said: {response}\nPresent your next argument.",
            )

        return debate

    async def judge_debate(self, topic: str, debate_text: str) -> DebateEval:
        system_prompt = """
You are an experienced debate judge tasked with evaluating debates.

For each debate, assess both sides based on four criteria:
1) Emotional Appeal
2) Clarity of Argument and Reasoning
3) Logical Arrangement of Arguments
4) Relevance to Debate Topic

For each criterion, provide a score from 0 to 1 for both the Pro and Con sides.
Also provide a total score for each side, pick a winner, and provide a reason.
"""

        user_prompt = f"""
Evaluate the debate on the topic: '{topic}'.

Debate transcript:
{debate_text}

Return a JSON response matching the provided schema.
"""

        response = self.client.models.generate_content(
            model="gemini-2.5-flash-lite",
            config=genai.types.GenerateContentConfig(
                system_instruction=system_prompt,
                response_mime_type="application/json",
                response_schema=DebateEval,
            ),
            contents=user_prompt,
        )
        return response.parsed

