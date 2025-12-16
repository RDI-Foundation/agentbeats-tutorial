from dataclasses import dataclass, field
from typing import Any

from openenv_core.env_server import Action, Observation, State


@dataclass
class Tau2Action(Action):
    action: str


@dataclass
class Tau2Observation(Observation):
    observation: str


@dataclass
class Tau2State(State):
    info: dict[str, Any] = field(default_factory=dict[str, Any])
