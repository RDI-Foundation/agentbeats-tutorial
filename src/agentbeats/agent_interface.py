"""
Standard agent interface definitions for hackathon compatibility.

All hackathon submissions must conform to these interfaces to ensure
cross-evaluation compatibility while allowing implementation creativity.
"""

from abc import ABC, abstractmethod
from typing import Any, Literal
from pydantic import BaseModel, HttpUrl, Field


# ============================================================================
# STANDARD REQUEST/RESPONSE SCHEMAS (REQUIRED FOR COMPATIBILITY)
# ============================================================================

class EvalRequest(BaseModel):
    """
    Standard evaluation request schema.

    Green agents MUST accept this format.
    Purple agents will be called via A2A protocol (standard messages).
    """
    participants: dict[str, HttpUrl] = Field(
        ...,
        description="Mapping of role names to agent URLs (e.g., {'defender': 'https://...'})"
    )
    config: dict[str, Any] = Field(
        ...,
        description="Evaluation configuration (domain, attack_vector, task, canaries, etc.)"
    )


class SecurityMetrics(BaseModel):
    """
    Standard security metrics that ALL green agents must report.

    This ensures fair comparison across different attack implementations.
    """
    # Green (attacker) metrics - REQUIRED
    asr: float = Field(..., ge=0.0, le=1.0, description="Attack Success Rate")
    coverage: float = Field(..., ge=0.0, le=1.0, description="Attack surface coverage")
    aps: float = Field(..., ge=0.0, description="Attacks Per Success (lower is better)")
    efficiency: float = Field(..., ge=0.0, description="Successful attacks per second")

    # Purple (defender) metrics - REQUIRED
    robustness: float = Field(..., ge=0.0, le=1.0, description="1 - ASR")
    task_fidelity: float = Field(..., ge=0.0, le=1.0, description="Task completion quality")

    # Attack details - REQUIRED
    total_attacks: int = Field(..., ge=0)
    successful_attacks: int = Field(..., ge=0)
    total_violations: int = Field(..., ge=0)
    elapsed_time: float = Field(..., gt=0.0)


class SecurityEvalResult(BaseModel):
    """
    Standard evaluation result schema.

    Green agents MUST produce this as an A2A artifact.
    This is what the cross-evaluation system expects.
    """
    # Evaluation context - REQUIRED
    domain: Literal["agent_security", "agent_safety"] = Field(
        ...,
        description="Evaluation domain"
    )
    attack_vector: Literal["dpi", "ipi"] = Field(
        ...,
        description="Attack vector used"
    )
    task_description: str = Field(
        ...,
        description="Task given to purple agent"
    )

    # Metrics - REQUIRED (must match SecurityMetrics schema)
    asr: float = Field(..., ge=0.0, le=1.0)
    coverage: float = Field(..., ge=0.0, le=1.0)
    aps: float = Field(..., ge=0.0)
    efficiency: float = Field(..., ge=0.0)
    robustness: float = Field(..., ge=0.0, le=1.0)
    task_fidelity: float = Field(..., ge=0.0, le=1.0)

    # Scores - REQUIRED
    green_score: float = Field(..., ge=0.0, le=100.0, description="Green agent score (0-100)")
    purple_score: float = Field(..., ge=0.0, le=100.0, description="Purple agent score (0-100)")

    # Attack details - REQUIRED
    total_violations: int = Field(..., ge=0)
    successful_attacks: int = Field(..., ge=0)
    elapsed_time: float = Field(..., gt=0.0)
    winner: Literal["attacker", "defender"]

    # Attack results - OPTIONAL (but recommended for debugging)
    attack_results: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Detailed attack attempt results"
    )


# ============================================================================
# CONFIGURATION SCHEMAS (WHAT TEAMS CAN CUSTOMIZE)
# ============================================================================

class CanaryConfig(BaseModel):
    """
    Canary configuration schema.

    Teams can define custom canaries, but must use these standard types.
    """
    type: Literal["data", "tool", "resource"] = Field(
        ...,
        description="Canary type"
    )
    description: str = Field(
        ...,
        description="Human-readable description of what this canary detects"
    )


class DataCanaryConfig(CanaryConfig):
    """Data leakage canary"""
    type: Literal["data"] = "data"
    value: str = Field(..., description="Secret value to detect in outputs")
    case_sensitive: bool = Field(default=False)


class ToolCanaryConfig(CanaryConfig):
    """Tool misuse canary"""
    type: Literal["tool"] = "tool"
    tool_name: str = Field(..., description="Tool that should not be called")
    allowed_params: dict[str, Any] | None = Field(
        default=None,
        description="Whitelist of safe parameters (None = tool should never be called)"
    )


class ResourceCanaryConfig(CanaryConfig):
    """Resource access canary"""
    type: Literal["resource"] = "resource"
    resource_pattern: str = Field(
        ...,
        description="Regex pattern for forbidden resources"
    )


class SecurityConfig(BaseModel):
    """
    Standard security evaluation configuration.

    This is what green agents receive in EvalRequest.config
    """
    # Required fields
    domain: Literal["agent_security", "agent_safety"]
    attack_vector: Literal["dpi", "ipi"]
    task_description: str

    # Canary configuration
    canaries: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Security canaries (trip wires)"
    )

    # Attack parameters
    max_turns: int = Field(default=5, ge=1, le=20)
    attack_attempts: int = Field(default=1, ge=1)
    timeout_seconds: int = Field(default=300, gt=0, le=600)

    # Optional metadata
    task_resources: list[str] = Field(default_factory=list)
    attack_mechanisms: list[str] = Field(default_factory=list)
    outcomes_targeted: list[str] = Field(default_factory=list)


# ============================================================================
# AGENT INTERFACE REQUIREMENTS
# ============================================================================

class GreenAgentInterface(ABC):
    """
    Interface that all green (attacker) agents must implement.

    Teams can implement this however they want, as long as they:
    1. Accept EvalRequest via A2A protocol
    2. Return SecurityEvalResult as A2A artifact
    3. Calculate all required metrics
    """

    @abstractmethod
    def validate_request(self, request: EvalRequest) -> tuple[bool, str]:
        """
        Validate evaluation request.

        Args:
            request: EvalRequest containing participants and config

        Returns:
            (is_valid, error_message)
        """
        pass

    @abstractmethod
    async def run_eval(self, request: EvalRequest, updater: Any) -> None:
        """
        Execute security evaluation.

        Must:
        1. Attack the purple agent at request.participants["defender"]
        2. Monitor for violations
        3. Calculate SecurityMetrics
        4. Produce SecurityEvalResult as A2A artifact

        Args:
            request: EvalRequest with purple agent URL and config
            updater: TaskUpdater for streaming progress
        """
        pass


class PurpleAgentInterface(ABC):
    """
    Interface that all purple (defender) agents must implement.

    Teams can implement this however they want, as long as they:
    1. Expose A2A server interface
    2. Accept messages from green agents
    3. Respond with text messages
    4. Handle multi-turn conversations
    """

    @abstractmethod
    async def handle_message(self, message: str, context_id: str | None) -> str:
        """
        Handle incoming message from green agent.

        Args:
            message: Text message from attacker
            context_id: Conversation context ID (for multi-turn)

        Returns:
            Response text
        """
        pass


# ============================================================================
# VALIDATION UTILITIES
# ============================================================================

def validate_green_agent_result(result: dict[str, Any]) -> tuple[bool, str]:
    """
    Validate that a green agent's result conforms to standard schema.

    Args:
        result: Result dictionary from green agent

    Returns:
        (is_valid, error_message)
    """
    try:
        # Try to parse as SecurityEvalResult
        SecurityEvalResult(**result)
        return True, "Valid"
    except Exception as e:
        return False, f"Invalid result schema: {e}"


def validate_eval_request(request: dict[str, Any]) -> tuple[bool, str]:
    """
    Validate that an evaluation request conforms to standard schema.

    Args:
        request: Request dictionary

    Returns:
        (is_valid, error_message)
    """
    try:
        # Try to parse as EvalRequest
        EvalRequest(**request)
        return True, "Valid"
    except Exception as e:
        return False, f"Invalid request schema: {e}"


def validate_security_config(config: dict[str, Any]) -> tuple[bool, str]:
    """
    Validate that security config conforms to standard schema.

    Args:
        config: Configuration dictionary

    Returns:
        (is_valid, error_message)
    """
    try:
        # Try to parse as SecurityConfig
        SecurityConfig(**config)
        return True, "Valid"
    except Exception as e:
        return False, f"Invalid config schema: {e}"


# ============================================================================
# COMPATIBILITY CHECKLIST
# ============================================================================

HACKATHON_COMPATIBILITY_CHECKLIST = """
Hackathon Agent Compatibility Checklist
========================================

GREEN AGENTS (Attackers) - REQUIRED:
✓ Implement A2A server interface (agent card, message handling)
✓ Accept EvalRequest format: {participants: {defender: URL}, config: {...}}
✓ Produce SecurityEvalResult as A2A artifact with ALL required fields:
  - domain, attack_vector, task_description
  - asr, coverage, aps, efficiency, robustness, task_fidelity
  - green_score, purple_score (0-100)
  - total_violations, successful_attacks, elapsed_time
  - winner ("attacker" or "defender")
✓ Calculate scores using standard weighting or clearly document custom weights
✓ Handle all 4 domain/vector combinations:
  - agent_security + dpi
  - agent_security + ipi
  - agent_safety + dpi
  - agent_safety + ipi

GREEN AGENTS - OPTIONAL (but encouraged):
○ Emit task updates during evaluation (for live monitoring)
○ Include detailed attack_results array for debugging
○ Support custom canary configurations
○ Implement multi-turn adaptive attacks

PURPLE AGENTS (Defenders) - REQUIRED:
✓ Implement A2A server interface (agent card, message handling)
✓ Accept text messages via A2A protocol
✓ Support multi-turn conversations (maintain context_id)
✓ Return text responses
✓ Handle all 4 attack scenarios without crashing

PURPLE AGENTS - OPTIONAL (but encouraged):
○ Implement security policies and defenses
○ Validate inputs for suspicious patterns
○ Emit task updates showing reasoning (for debugging)
○ Handle edge cases gracefully

TESTING YOUR AGENT:
1. Test against reference agents (baseline_defender, red_team_evaluator)
2. Verify A2A agent card is accessible
3. Check response times (< 5 min per evaluation)
4. Validate output schema with validate_green_agent_result()
5. Test all 4 domain/vector combinations

SUBMISSION REQUIREMENTS:
1. Public URL (via Cloudflare Tunnel, ngrok, or hosted)
2. Agent card accessible at {url}/.well-known/a2a/agent-card
3. Stable and responsive during evaluation period
4. Reasonable resource usage (don't DoS the system)
"""


def print_compatibility_checklist():
    """Print the compatibility checklist"""
    print(HACKATHON_COMPATIBILITY_CHECKLIST)
