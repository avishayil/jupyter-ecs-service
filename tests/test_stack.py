import os

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

from cdk.jupyter_ecs_service.constants import BASE_NAME
from cdk.jupyter_ecs_service.jupyter_ecs_service_stack import (
    JupyterEcsServiceStack,
)

# The password previously hardcoded in config.yaml. Kept here purely so the
# regression test can assert it never leaks into the synthesized template.
OLD_HARDCODED_PASSWORD = "***REMOVED***"


@pytest.fixture(scope="module")
def template():
    # Provide the env vars the stack requires so synth works offline and does
    # not attempt a network call to resolve the deployer IP.
    os.environ["JUPYTER_ADMIN_TEMP_PASSWORD"] = "TestOnlyTempPassw0rd!"
    os.environ["DEPLOYER_IP_CIDR"] = "203.0.113.10/32"

    app = cdk.App()
    stack = JupyterEcsServiceStack(
        app,
        BASE_NAME,
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )
    return Template.from_stack(stack)


def test_ecs_service_present(template):
    template.resource_count_is("AWS::ECS::Service", 1)


def test_fargate_task_definition_sizing(template):
    template.has_resource_properties(
        "AWS::ECS::TaskDefinition",
        {
            "Cpu": "512",
            "Memory": "2048",
            "RequiresCompatibilities": Match.array_with(["FARGATE"]),
        },
    )


def test_internet_facing_alb(template):
    template.has_resource_properties(
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        {"Scheme": "internet-facing"},
    )


def test_https_listener_on_443(template):
    template.has_resource_properties(
        "AWS::ElasticLoadBalancingV2::Listener",
        {"Protocol": "HTTPS", "Port": 443},
    )


def test_cognito_user_pool_present(template):
    template.resource_count_is("AWS::Cognito::UserPool", 1)


def test_cognito_user_pool_client_present(template):
    template.resource_count_is("AWS::Cognito::UserPoolClient", 1)


def test_cognito_user_pool_domain_present(template):
    template.resource_count_is("AWS::Cognito::UserPoolDomain", 1)


def test_efs_encrypted_with_kms(template):
    template.has_resource_properties(
        "AWS::EFS::FileSystem",
        {"Encrypted": True, "KmsKeyId": Match.any_value()},
    )
    template.resource_count_is("AWS::KMS::Key", 1)


def test_at_least_two_iam_roles(template):
    roles = template.find_resources("AWS::IAM::Role")
    assert len(roles) >= 2


def test_old_hardcoded_password_absent(template):
    rendered = str(template.to_json())
    assert OLD_HARDCODED_PASSWORD not in rendered
