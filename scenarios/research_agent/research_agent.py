"""
Research Agent (Purple Agent)
This agent performs research tasks given by green agents.
"""

import os
from dataclasses import dataclass

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    TaskStatus,
    Message,
    TextPart,
    UnsupportedOperationError,
)
from a2a.utils.errors import ServerError

# You can use any LLM provider
import openai


class ResearchAgent(AgentExecutor):
    """
    Purple Agent that performs research tasks.
    
    This agent:
    1. Receives research questions from the green agent
    2. Uses an LLM to generate comprehensive responses
    3. Returns structured research output
    """
    
    def __init__(self):
        self.client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = "gpt-4o-mini"  # Cost-effective model
    
    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue
    ) -> None:
        """Process incoming research requests."""
        
        # Extract the research question
        message = context.message
        question = ""
        for part in message.parts:
            if hasattr(part, 'text'):
                question += part.text
        
        await event_queue.enqueue_event(
            TaskStatus(state="working", message="Researching...")
        )
        
        try:
            # Perform research using LLM
            response = await self._do_research(question)
            
            # Send response back
            await event_queue.enqueue_event(
                Message(
                    role="agent",
                    parts=[TextPart(text=response)]
                )
            )
            
            await event_queue.enqueue_event(
                TaskStatus(state="completed", message="Research complete!")
            )
            
        except Exception as e:
            await event_queue.enqueue_event(
                TaskStatus(state="failed", message=f"Error: {str(e)}")
            )
    
    async def _do_research(self, question: str) -> str:
        """
        Perform research on the given question.
        
        In a production agent, you might:
        - Use web search APIs
        - Query knowledge bases
        - Use RAG systems
        - Combine multiple sources
        """
        
        system_prompt = """You are a research assistant. When given a topic:
1. Provide a comprehensive, well-structured response
2. Cite sources and references where applicable
3. Include relevant statistics and data
4. Organize information clearly with sections
5. Be accurate and factual

Format your response with clear sections and always mention sources."""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": question}
            ],
            max_tokens=1000,
            temperature=0.7
        )
        
        return response.choices[0].message.content

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise ServerError(error=UnsupportedOperationError())


def create_agent_card(card_url: str) -> AgentCard:
    """Define the agent's capabilities."""
    skill = AgentSkill(
        id="research",
        name="Research",
        description="Researches topics and provides comprehensive answers with sources",
        tags=["research"],
        examples=["Research the following topic and provide a comprehensive answer with sources: ..."],
    )
    return AgentCard(
        name="Research Agent",
        description="AI agent that performs research and information synthesis",
        url=card_url,
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[skill],
    )