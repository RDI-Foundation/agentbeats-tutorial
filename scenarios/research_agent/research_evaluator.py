"""
Research Agent Evaluator (Green Agent)
This agent evaluates research capabilities of purple agents.
"""

import json
import asyncio
from dataclasses import dataclass
from typing import Any
from datetime import datetime

# Import A2A SDK components
from a2a.server.agent_execution import AgentExecutor
from a2a.server.events import EventQueue
from a2a.types import TaskStatus, Message, TextPart, DataPart
from a2a.client import A2AClient

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
        context: Any,
        event_queue: EventQueue
    ) -> None:
        """Main execution method called when assessment starts."""
        
        # Get the assessment request from context
        request = context.message.parts[0].data
        participants = request.get("participants", {})
        config = request.get("config", {})
        
        # Update status
        await event_queue.enqueue_event(
            TaskStatus(
                state="working",
                message="Starting research evaluation..."
            )
        )
        
        results = []
        
        # Evaluate each participant
        for role, endpoint in participants.items():
            if role == "researcher":  # Purple agent role
                participant_results = await self._evaluate_participant(
                    endpoint, event_queue
                )
                results.append({
                    "participant": role,
                    "scores": participant_results
                })
        
        # Calculate final scores
        final_results = self._calculate_final_scores(results)
        
        # Send results as artifact
        await event_queue.enqueue_event(
            Message(
                role="agent",
                parts=[DataPart(data=json.dumps(final_results))]
            )
        )
        
        await event_queue.enqueue_event(
            TaskStatus(state="completed", message="Evaluation complete!")
        )
    
    async def _evaluate_participant(
        self,
        endpoint: str,
        event_queue: EventQueue
    ) -> dict:
        """Evaluate a single participant on all tasks."""
        
        scores = []
        client = A2AClient(endpoint)
        
        for task in self.tasks:
            # Send task to participant
            await event_queue.enqueue_event(
                TaskStatus(
                    state="working",
                    message=f"Sending task: {task.topic[:50]}..."
                )
            )
            
            try:
                # Send the research request
                response = await client.send_message(
                    Message(
                        role="user",
                        parts=[TextPart(text=f"Research the following topic and provide a comprehensive answer with sources: {task.topic}")]
                    ),
                    timeout=task.time_limit_seconds
                )
                
                # Score the response
                score = self._score_response(response, task)
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
    
    def _score_response(self, response: Message, task: ResearchTask) -> dict:
        """
        Score a response based on evaluation criteria.
        In a real implementation, this might use an LLM-as-judge approach.
        """
        text = ""
        for part in response.parts:
            if hasattr(part, 'text'):
                text += part.text
        
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
            "participants": {},
            "results": []
        }
        
        for result in results:
            participant = result["participant"]
            scores = result["scores"]
            
            total_score = sum(s.get("score", 0) for s in scores)
            max_score = sum(s.get("max_score", 100) for s in scores)
            
            final["participants"][participant] = participant
            final["results"].append({
                "participant": participant,
                "total_score": total_score,
                "max_score": max_score,
                "pass_rate": (total_score / max_score * 100) if max_score > 0 else 0,
                "task_scores": scores
            })
        
        return final


# Server setup
def create_agent_card():
    """Define the agent's capabilities."""
    return {
        "name": "Research Evaluator",
        "description": "Evaluates AI agents' research and information synthesis capabilities",
        "skills": [
            {
                "name": "research_evaluation",
                "description": "Evaluates research quality, source citation, and comprehensiveness"
            }
        ]
    }