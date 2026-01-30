"""
Research Agent Evaluator (Green Agent)
This agent evaluates research capabilities of purple agents.
"""

import json
import asyncio
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

# Import A2A SDK components
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.client import (
    A2ACardResolver,
    ClientConfig,
    ClientFactory,
)
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    InvalidRequestError,
    Message,
    Part,
    TextPart,
    DataPart,
    TaskState,
    Role,
    UnsupportedOperationError,
)
import httpx
from a2a.utils import new_agent_text_message, new_task
from a2a.utils.errors import ServerError

TERMINAL_STATES = {
    TaskState.completed,
    TaskState.canceled,
    TaskState.failed,
    TaskState.rejected,
}

DEFAULT_TIMEOUT = 300

def _create_message(text: str) -> Message:
    return Message(
        kind="message",
        role=Role.user,
        parts=[Part(TextPart(kind="text", text=text))],
        message_id=uuid4().hex,
    )

def _merge_parts(parts: list[Part]) -> str:
    chunks = []
    for part in parts:
        if isinstance(part.root, TextPart):
            chunks.append(part.root.text)
        elif isinstance(part.root, DataPart):
            chunks.append(json.dumps(part.root.data, indent=2))
    return "\n".join(chunks)

async def _send_message(text: str, base_url: str) -> str:
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as httpx_client:
        resolver = A2ACardResolver(httpx_client=httpx_client, base_url=base_url)
        agent_card = await resolver.get_agent_card()
        config = ClientConfig(
            httpx_client=httpx_client,
            streaming=False,
        )
        client = ClientFactory(config).create(agent_card)
        outbound_msg = _create_message(text)
        last_event = None
        async for event in client.send_message(outbound_msg):
            last_event = event
        if isinstance(last_event, Message):
            return _merge_parts(last_event.parts)
        if isinstance(last_event, tuple):
            task, _update = last_event
            msg = task.status.message
            output = _merge_parts(msg.parts) if msg else ""
            if task.artifacts:
                for artifact in task.artifacts:
                    if output:
                        output += "\n"
                    output += _merge_parts(artifact.parts)
            return output
        return ""

@dataclass
class ResearchTask:
    """Defines a research task for evaluation."""
    topic: str
    expected_sources: int
    time_limit_seconds: int
    criteria: list[str]

class ResearchEvaluator(AgentExecutor):
    """
    Green Agent that evaluates research capabilities.
    
    This evaluator:
    1. Sends research topics to purple agents
    2. Collects their research outputs
    3. Scores based on criteria
    """
    
    def __init__(self):
        self.tasks = [
            ResearchTask(
                topic="What are the latest developments in quantum computing?",
                expected_sources=3,
                time_limit_seconds=120,
                criteria=["accuracy", "source_quality", "comprehensiveness"]
            ),
            ResearchTask(
                topic="Explain the impact of AI on healthcare",
                expected_sources=3,
                time_limit_seconds=120,
                criteria=["accuracy", "source_quality", "comprehensiveness"]
            )
        ]
    
    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue
    ) -> None:
        """Main execution method called when assessment starts."""
        
        message = context.message
        if not message:
            raise ServerError(error=InvalidRequestError(message="Missing message in request"))

        task = context.current_task
        if task and task.status.state in TERMINAL_STATES:
            raise ServerError(
                error=InvalidRequestError(
                    message=f"Task {task.id} already processed (state: {task.status.state})"
                )
            )

        if not task:
            task = new_task(message)
            await event_queue.enqueue_event(task)

        context_id = task.context_id
        updater = TaskUpdater(event_queue, task.id, context_id)

        # Get the assessment request from context
        request = {}
        if message.parts:
            part = message.parts[0].root
            if isinstance(part, DataPart):
                request = part.data
            elif isinstance(part, TextPart):
                request = json.loads(part.text)
        participants = request.get("participants", {})
        config = request.get("config", {})
        
        await updater.start_work(
            new_agent_text_message("Starting research evaluation...", context_id=context_id, task_id=task.id)
        )
        
        results = []
        
        # Evaluate each participant
        for role, endpoint in participants.items():
            if role == "researcher":  # Purple agent role
                participant_results = await self._evaluate_participant(
                    endpoint, event_queue, updater, context_id, task.id
                )
                results.append({
                    "participant": role,
                    "scores": participant_results
                })
        
        # Calculate final scores
        final_results = self._calculate_final_scores(results)
        
        # Send results as artifact
        await updater.add_artifact([Part(DataPart(data=final_results))])

        await updater.complete(
            new_agent_text_message("Evaluation complete!", context_id=context_id, task_id=task.id)
        )
    
    async def _evaluate_participant(
        self,
        endpoint: str,
        event_queue: EventQueue,
        updater: TaskUpdater,
        context_id: str,
        task_id: str,
    ) -> dict:
        """Evaluate a single participant on all tasks."""
        
        scores = []
        for task in self.tasks:
            await updater.update_status(
                TaskState.working,
                new_agent_text_message(
                    f"Sending task: {task.topic[:50]}...",
                    context_id=context_id,
                    task_id=task_id,
                ),
            )
            try:
                output = await _send_message(
                    f"Research the following topic and provide a comprehensive answer with sources: {task.topic}",
                    endpoint,
                )
                score = self._score_response(output, task)
                scores.append(score)
            except asyncio.TimeoutError:
                scores.append({
                    "task": task.topic,
                    "score": 0,
                    "reason": "Timeout"
                })
            except Exception as e:
                scores.append({
                    "task": task.topic,
                    "score": 0,
                    "reason": str(e)
                })
        
        return scores
    
    def _score_response(self, response_text: str, task: ResearchTask) -> dict:
        """
        Score a response based on evaluation criteria.
        In a real implementation, this might use an LLM-as-judge approach.
        """
        text = response_text or ""
        
        # Simple scoring logic (replace with LLM-based evaluation for production)
        score = 0
        
        # Check length (proxy for comprehensiveness)
        if len(text) > 500:
            score += 30
        elif len(text) > 200:
            score += 15
        
        # Check for sources mentioned
        source_keywords = ["according to", "source:", "reference", "study shows", "research indicates"]
        sources_found = sum(1 for kw in source_keywords if kw.lower() in text.lower())
        score += min(sources_found * 10, 40)
        
        # Check relevance (simple keyword match)
        topic_words = task.topic.lower().split()
        relevant_words = sum(1 for word in topic_words if word in text.lower())
        score += min(relevant_words * 5, 30)
        
        return {
            "task": task.topic,
            "score": min(score, 100),
            "max_score": 100
        }
    
    def _calculate_final_scores(self, results: list) -> dict:
        """Calculate final aggregated scores."""
        
        final = {
            "timestamp": datetime.utcnow().isoformat(),
            "results": []
        }
        
        for result in results:
            participant = result["participant"]
            scores = result["scores"]
            
            total_score = sum(s.get("score", 0) for s in scores)
            max_score = sum(s.get("max_score", 100) for s in scores)
            
            final["results"].append({
                "participant": participant,
                "total_score": total_score,
                "max_score": max_score,
                "pass_rate": (total_score / max_score * 100) if max_score > 0 else 0,
                "task_scores": scores
            })
        
        return final

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise ServerError(error=UnsupportedOperationError())


# Server setup
def create_agent_card(card_url: str) -> AgentCard:
    """Define the agent's capabilities."""
    skill = AgentSkill(
        id="research_evaluation",
        name="Research Evaluation",
        description="Evaluates research quality, source citation, and comprehensiveness",
        tags=["evaluation", "research"],
        examples=["Evaluate research responses for accuracy, sources, and depth."],
    )
    return AgentCard(
        name="Research Evaluator",
        description="Evaluates AI agents' research and information synthesis capabilities",
        url=card_url,
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[skill],
    )