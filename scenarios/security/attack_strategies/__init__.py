"""
Attack strategy modules for security evaluations.

Each module implements attack generation for a specific domain/vector combination:
- agent_security_dpi: Direct prompt injection attacks on tool/data security
- agent_security_ipi: Indirect prompt injection via RAG/resources on tool/data security
- agent_safety_dpi: Direct jailbreak attempts
- agent_safety_ipi: Indirect jailbreaks via metadata/resources
"""

from abc import ABC, abstractmethod
from typing import Any


class AttackStrategy(ABC):
    """Base class for attack strategies"""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.turn_count = 0
        self.previous_responses: list[str] = []

    @abstractmethod
    async def generate_attack(self, turn: int, previous_response: str | None = None) -> str:
        """Generate attack prompt for the given turn"""
        pass

    @abstractmethod
    def get_mechanisms(self) -> list[str]:
        """Get list of attack mechanisms used"""
        pass

    @abstractmethod
    def get_outcomes_targeted(self) -> list[str]:
        """Get list of outcomes this strategy targets"""
        pass

    def update_state(self, response: str) -> None:
        """Update strategy state with purple agent response"""
        self.previous_responses.append(response)
        self.turn_count += 1

    def should_continue(self, max_turns: int) -> bool:
        """Check if strategy should continue"""
        return self.turn_count < max_turns
