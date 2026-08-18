import os
import sys

# Ensure the repository root is importable so `from cdk.jupyter_ecs_service...`
# resolves regardless of the directory pytest is invoked from.
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# The stack reads relative paths (config.yaml, docker/admins) at synth time, so
# run tests from the repository root.
os.chdir(REPO_ROOT)
