from dataclasses import dataclass, field
from typing import Any
import uuid

import gymnasium as gym

from openenv_core.env_server import Action, Environment, Observation, State
from tau2.gym import TAU_BENCH_ENV_ID, register_gym_agent

from tau2_models import Tau2Action, Tau2Observation, Tau2State


# https://github.com/sierra-research/tau2-bench/blob/main/src/tau2/gym/README.md
# https://github.com/meta-pytorch/OpenEnv/blob/fb169f8c660df722f538160b3ce636de3312a756/src/envs/README.md


register_gym_agent()


class Tau2Environment(Environment):
    def __init__(
        self,
        domain: str,
        task_id: str,
        env_args: Any,
    ):
        super().__init__()
        self._state = Tau2State()
        self._gym_env: gym.Env[str, str] = gym.make(
            TAU_BENCH_ENV_ID,
            domain=domain,
            task_id=task_id,
            **env_args,
        )

    def reset(self) -> Tau2Observation:
        self._state = Tau2State(episode_id=str(uuid.uuid4()))
        observation, info = self._gym_env.reset()
        self._state.info = info
        return Tau2Observation(observation=observation)

    def step(self, action: Action) -> Tau2Observation:
        assert isinstance(action, Tau2Action)
        self._state.step_count += 1
        observation, reward, terminated, truncated, info = self._gym_env.step(action.action)
        self._state.info = info
        return Tau2Observation(
            observation=observation,
            done=terminated or truncated,
            reward=float(reward),
        )

    @property
    def state(self) -> Tau2State:
        return self._state
