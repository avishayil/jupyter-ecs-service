import yaml
import urllib.request

from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_efs as efs,
    aws_iam as iam,
    aws_ecs_patterns as ecs_patterns,
    aws_cognito as cognito,
    aws_elasticloadbalancingv2 as lb,
    aws_certificatemanager as acm,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
    custom_resources as cr,
    aws_logs as logs,
    aws_kms as kms,
    core as cdk
)

from constants import BASE_NAME


class JupyterEcsServiceStack(cdk.Stack):

    def __init__(self, scope: cdk.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # General configuration variables

        config_yaml = yaml.load(
            open('config.yaml'), Loader=yaml.FullLoader)

        domain_prefix = config_yaml['domain_prefix']

        application_prefix = 'jupyter-' + domain_prefix
        suffix = f'secure'.lower()

        # Define IAM roles and policies

        jupyter_ecs_task_role = iam.Role(
            self,
            f'{BASE_NAME}TaskRole',
            assumed_by=iam.ServicePrincipal('ecs-tasks.amazonaws.com')
        )

        jupyter_ecs_task_role.add_to_policy(
            iam.PolicyStatement(
                resources=['*'],
                actions=['cloudwatch:PutMetricData', 'cloudwatch:ListMetrics']
            )
        )

        jupyter_ecs_task_role.add_to_policy(
            iam.PolicyStatement(
                resources=['*'],
                actions=[
                    'logs:CreateLogStream',
                    'logs:DescribeLogGroups',
                    'logs:DescribeLogStreams',
                    'logs:CreateLogGroup',
                    'logs:PutLogEvents',
                    'logs:PutRetentionPolicy'
                ]
            )
        )

        jupyter_ecs_task_role.add_to_policy(
            iam.PolicyStatement(
                resources=['*'],
                actions=['ec2:DescribeRegions']
            )
        )

        jupyter_ecs_task_execution_role = iam.Role(
            self, f'{BASE_NAME}TaskExecutionRole',
            assumed_by=iam.ServicePrincipal('ecs-tasks.amazonaws.com')
        )

        jupyter_ecs_task_execution_role.add_managed_policy(
            iam.ManagedPolicy.from_managed_policy_arn(
                self,
                f'{BASE_NAME}ServiceRole',
                managed_policy_arn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'
            )
        )

        # VPC and security groups

        jupyter_vpc = ec2.Vpc(
            self, f'{BASE_NAME}Vpc',
            max_azs=2
        )

        jupyter_lb_security_group = ec2.SecurityGroup(
            self,
            f'{BASE_NAME}LBSG',
            vpc=jupyter_vpc,
            description='Jupyter ECS service load balancer security group',
            allow_all_outbound=True
        )

        # Open ingress to the deploying computer public IP

        my_ip_cidr = urllib.request.urlopen(
            'http://checkip.amazonaws.com').read().decode('utf-8').strip() + '/32'
        jupyter_lb_security_group.add_ingress_rule(
            peer=ec2.Peer.ipv4(cidr_ip=my_ip_cidr),
            connection=ec2.Port.tcp(port=443),
            description='Allow HTTPS traffic'
        )

        jupyter_service_security_group = ec2.SecurityGroup(
            self,
            f'{BASE_NAME}ServiceSG',
            vpc=jupyter_vpc,
            description='Jupyter ECS service containers security group',
            allow_all_outbound=True
        )

        jupyter_efs_security_group = ec2.SecurityGroup(
            self,
            f'{BASE_NAME}EFSSG',
            vpc=jupyter_vpc,
            description='Jupyter shared filesystem security group',
            allow_all_outbound=True
        )

        jupyter_efs_security_group.connections.allow_from(
            jupyter_service_security_group,
            port_range=ec2.Port.tcp(2049),
            description='Allow NFS from ECS Service containers'
        )

        # EFS FileSystem

        jupyter_efs_cmk = kms.Key(
            self,
            f'{BASE_NAME}EFSCMK',
            alias='jupyter-ecs-efs-cmk',
            description='CMK for EFS Encryption',
            enabled=True,
            enable_key_rotation=True,
            trust_account_identities=True,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )

        jupyter_efs = efs.FileSystem(
            self,
            f'{BASE_NAME}EFS',
            vpc=jupyter_vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE),
            security_group=jupyter_efs_security_group,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            encrypted=True,
            kms_key=jupyter_efs_cmk
        )

        jupyter_efs_mount_point = ecs.MountPoint(
            container_path='/home',
            source_volume='efs-volume',
            read_only=False
        )

        # ECS clusters ALB, hosted zone records and certificates

        jupyter_cluster = ecs.Cluster(
            self, f'{BASE_NAME}Cluster',
            vpc=jupyter_vpc
        )

        jupyter_ecs_loadbalancer = lb.ApplicationLoadBalancer(
            self,
            f'{BASE_NAME}ServiceALB',
            vpc=jupyter_vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            internet_facing=True
        )

        jupyter_ecs_loadbalancer.add_security_group(
            ec2.SecurityGroup.from_security_group_id(
                self,
                f'{BASE_NAME}ImportedLBSG',
                security_group_id=jupyter_lb_security_group.security_group_id,
                mutable=False
            )
        )

        jupyter_hosted_zone = route53.PublicHostedZone.from_hosted_zone_attributes(
            self,
            f'{BASE_NAME}HostedZone',
            hosted_zone_id=config_yaml['hosted_zone_id'],
            zone_name=config_yaml['hosted_zone_name']
        )

        jupyter_route53_record = route53.ARecord(
            self,
            f'{BASE_NAME}LBRecord',
            zone=jupyter_hosted_zone,
            record_name=application_prefix,
            target=route53.RecordTarget(alias_target=(
                route53_targets.LoadBalancerTarget(jupyter_ecs_loadbalancer)))
        )

        jupyter_certificate = acm.Certificate(
            self,
            f'{BASE_NAME}Certificate',
            domain_name='*.' + jupyter_hosted_zone.zone_name,
            validation=acm.CertificateValidation.from_dns(
                hosted_zone=jupyter_hosted_zone)
        )

        # User pool and user pool OAuth client

        cognito_user_pool = cognito.UserPool(
            self,
            f'{BASE_NAME}UserPool',
            removal_policy=cdk.RemovalPolicy.DESTROY
        )

        cognito_user_pool_domain = cognito.UserPoolDomain(
            self,
            f'{BASE_NAME}UserPoolDomain',
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix=application_prefix + '-' + suffix),
            user_pool=cognito_user_pool
        )

        cognito_app_client = cognito.UserPoolClient(
            self,
            f'{BASE_NAME}UserPoolClient',
            user_pool=cognito_user_pool,
            generate_secret=True,
            supported_identity_providers=[
                cognito.UserPoolClientIdentityProvider.COGNITO],
            prevent_user_existence_errors=True,
            o_auth=cognito.OAuthSettings(
                callback_urls=[
                    'https://' + jupyter_route53_record.domain_name + '/hub/oauth_callback'],
                flows=cognito.OAuthFlows(
                    authorization_code_grant=True,
                    implicit_code_grant=True
                ),
                scopes=[cognito.OAuthScope.PROFILE, cognito.OAuthScope.OPENID]
            )
        )

        describe_cognito_user_pool_client = cr.AwsCustomResource(
            self,
            f'{BASE_NAME}UserPoolClientIDResource',
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE),
            on_create=cr.AwsSdkCall(
                service='CognitoIdentityServiceProvider',
                action='describeUserPoolClient',
                parameters={'UserPoolId': cognito_user_pool.user_pool_id,
                            'ClientId': cognito_app_client.user_pool_client_id},
                physical_resource_id=cr.PhysicalResourceId.of(
                    cognito_app_client.user_pool_client_id)
            )
        )

        cognito_user_pool_client_secret = describe_cognito_user_pool_client.get_response_field(
            'UserPoolClient.ClientSecret')

        # ECS Task definition and volumes

        jupyter_ecs_task_definition = ecs.FargateTaskDefinition(
            self,
            f'{BASE_NAME}TaskDefinition',
            cpu=512,
            memory_limit_mib=2048,
            execution_role=jupyter_ecs_task_execution_role,
            task_role=jupyter_ecs_task_role
        )

        jupyter_ecs_task_definition.add_volume(
            name='efs-volume',
            efs_volume_configuration=ecs.EfsVolumeConfiguration(
                file_system_id=jupyter_efs.file_system_id
            )
        )

        # ECS Container definition, service, target group and ALB attachment

        jupyter_ecs_container = jupyter_ecs_task_definition.add_container(
            f'{BASE_NAME}Container',
            image=ecs.ContainerImage.from_registry(
                config_yaml['container_image']),
            privileged=False,
            port_mappings=[
                ecs.PortMapping(
                    container_port=8000,
                    host_port=8000,
                    protocol=ecs.Protocol.TCP
                )
            ],
            logging=ecs.LogDriver.aws_logs(
                stream_prefix=f'{BASE_NAME}ContainerLogs-',
                log_retention=logs.RetentionDays.ONE_WEEK
            ),
            environment={
                'OAUTH_CALLBACK_URL': 'https://' + jupyter_route53_record.domain_name + '/hub/oauth_callback',
                'OAUTH_CLIENT_ID': cognito_app_client.user_pool_client_id,
                'OAUTH_CLIENT_SECRET': cognito_user_pool_client_secret,
                'OAUTH_LOGIN_SERVICE_NAME': config_yaml['oauth_login_service_name'],
                'OAUTH_LOGIN_USERNAME_KEY': config_yaml['oauth_login_username_key'],
                'OAUTH_AUTHORIZE_URL': 'https://' + cognito_user_pool_domain.domain_name + '.auth.' + self.region + '.amazoncognito.com/oauth2/authorize',
                'OAUTH_TOKEN_URL': 'https://' + cognito_user_pool_domain.domain_name + '.auth.' + self.region + '.amazoncognito.com/oauth2/token',
                'OAUTH_USERDATA_URL': 'https://' + cognito_user_pool_domain.domain_name + '.auth.' + self.region + '.amazoncognito.com/oauth2/userInfo',
                'OAUTH_SCOPE': ','.join(config_yaml['oauth_scope'])
            }
        )

        jupyter_ecs_container.add_mount_points(jupyter_efs_mount_point)

        jupyter_ecs_service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self, f'{BASE_NAME}Service',
            cluster=jupyter_cluster,
            task_definition=jupyter_ecs_task_definition,
            load_balancer=jupyter_ecs_loadbalancer,
            desired_count=config_yaml['num_containers'],
            security_groups=[jupyter_service_security_group],
            open_listener=False
        )

        jupyter_ecs_service.target_group.configure_health_check(
            path='/hub',
            enabled=True,
            healthy_http_codes='200-302'
        )

        jupyter_ecs_loadbalancer.add_listener(
            f'{BASE_NAME}ServiceALBListener',
            protocol=lb.ApplicationProtocol.HTTPS,
            port=443,
            certificates=[jupyter_certificate],
            default_action=lb.ListenerAction.forward(
                target_groups=[jupyter_ecs_service.target_group])
        )

        # Cognito admin users from admins file

        with open('docker/admins') as fp:
            lines = fp.readlines()
            for line in lines:
                cr.AwsCustomResource(
                    self,
                    f'{BASE_NAME}UserPoolAdminUserResource',
                    policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                        resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE),
                    on_create=cr.AwsSdkCall(
                        service='CognitoIdentityServiceProvider',
                        action='adminCreateUser',
                        parameters={'UserPoolId': cognito_user_pool.user_pool_id,
                                    'Username': line.strip(),
                                    'TemporaryPassword': config_yaml['admin_temp_password']},
                        physical_resource_id=cr.PhysicalResourceId.of(
                            cognito_user_pool.user_pool_id)
                    )
                )

        # Output the service URL to CloudFormation outputs

        cdk.CfnOutput(
            self,
            f'{BASE_NAME}JupyterHubURL',
            value='https://' + jupyter_route53_record.domain_name
        )
