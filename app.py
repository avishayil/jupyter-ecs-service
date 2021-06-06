#!/usr/bin/env python3
import os

from aws_cdk import core as cdk
from cdk.jupyter_ecs_service.jupyter_ecs_service_stack import JupyterEcsServiceStack
from cdk.jupyter_ecs_service.constants import BASE_NAME


app = cdk.App()
JupyterEcsServiceStack(app, BASE_NAME)

app.synth()
