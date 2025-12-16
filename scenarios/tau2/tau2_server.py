import os
import json
from openenv_core.env_server import create_fastapi_app

from tau2_models import Tau2Action, Tau2Observation
from tau2_env import Tau2Environment


# https://github.com/meta-pytorch/OpenEnv/blob/fb169f8c660df722f538160b3ce636de3312a756/src/envs/README.md


env = Tau2Environment(
    domain=os.environ.get("TAU2_DOMAIN", "airline"),
    task_id=os.environ.get("TAU2_TASK_ID", "0"),
    env_args=json.loads(os.environ.get("TAU2_ENV_ARGS_JSON", "{}")),
)
app = create_fastapi_app(env, Tau2Action, Tau2Observation)
