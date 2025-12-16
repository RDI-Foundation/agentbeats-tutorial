from typing import Any

from openenv_core.client_types import StepResult
from openenv_core.http_env_client import HTTPEnvClient

from tau2_models import Tau2Action, Tau2Observation, Tau2State


# https://github.com/meta-pytorch/OpenEnv/blob/fb169f8c660df722f538160b3ce636de3312a756/src/envs/README.md


class Tau2Env(HTTPEnvClient[Tau2Action, Tau2Observation]):
    def _step_payload(self, action: Tau2Action) -> dict[str, Any]:
        return {"action": action.action}
    
    def _parse_result(self, payload: dict[str, Any]) -> StepResult[Tau2Observation]:
        obs = Tau2Observation(**payload["observation"])
        return StepResult(
            observation=obs,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )
    
    def _parse_state(self, payload: dict[str, Any]) -> Tau2State:
        return Tau2State(**payload)
