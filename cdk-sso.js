import { Stack, type StackProps, Duration } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as events from 'aws-cdk-lib/aws-events';
import * as events_targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as lambda_destinations from 'aws-cdk-lib/aws-lambda-destinations';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as stepfunctions from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import type { Construct } from 'constructs';
import {
  addOpCfnTags, identityStoreId, ssoInstanceArn, bitbucketBotUser,
  opHubAccounts
} from './common';

export class AwsSsoOperationsStack extends Stack {
  private readonly ssoUserPermissionsBucket: s3.Bucket;
  private readonly ssoUserPermissionsLambda: lambda.Function;
  private readonly ssoUserPermissionsScheduleEvent: events.Rule;
  private readonly ssoValidatorLambda: lambda.Function;
  private readonly ssoAssignmentAndProvisionLambda: lambda.Function;
  private readonly ssoCfnPullRequestLambda: lambda.Function;
  private readonly accountDataPullRequestLambda: lambda.Function;
  private readonly ssoErrorHandlingLambda: lambda.Function;
  private readonly ssoErrorHandlingLambdasRole: iam.Role;
  private readonly ssoLambdasRole: iam.Role;
  private readonly ssoVpcLambdasRole: iam.Role;
  private readonly ssoStateMachineRole: iam.Role;
  private readonly ssoStateMachine: stepfunctions.StateMachine;
  private readonly ssoStateMachineArn: ssm.StringParameter;
  private readonly ssoOperationsNotificationsTopic: sns.Topic;
  private readonly ssoOperationsNotificationsTopicArn: ssm.StringParameter;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    this.ssoOperationsNotificationsTopic = new sns.Topic(this, 'sso-operations-notication-topic');
    addOpCfnTags(this.ssoOperationsNotificationsTopic);

    this.ssoOperationsNotificationsTopicArn = new ssm.StringParameter(this, 'sso-operations-notication-topic-arn', {
      description: 'CFN SSO operations notifications SNS topic arn',
      parameterName: '/cloudfoundation/snstopic/ssoOperationsNotifications/arn',
      stringValue: this.ssoOperationsNotificationsTopic.topicArn
    });
    addOpCfnTags(this.ssoOperationsNotificationsTopicArn);

    this.ssoErrorHandlingLambdasRole = new iam.Role(this, 'sso-error-handling-lambdas-role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')],
      inlinePolicies: {
        'sns-publish': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['sns:Publish'],
              resources: [this.ssoOperationsNotificationsTopic.topicArn]
            })
          ]
        })
      }
    });
    addOpCfnTags(this.ssoErrorHandlingLambdasRole);

    this.ssoLambdasRole = new iam.Role(this, 'sso-lambdas-role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')],
      inlinePolicies: {
        'read-account-list-from-bucket': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['s3:GetObject'],
              resources: ['arn:aws:s3:::op-account-data-production/account-list.json']
            })
          ]
        }),
        'read-write-sso-user-permissions-bucket': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['s3:*'],
              resources: ['arn:aws:s3:::op-sso-user-permissions/*']
            })
          ]
        }),
        'sso-admin-access': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'sso:List*',
                'sso:Describe*',
                'sso:ProvisionPermissionSet',
                'sso:CreateAccountAssignment',
                'sso:DeleteAccountAssignment',
                'identitystore:DescribeUser',
                'identitystore:ListUsers',
                'identitystore:ListGroups',
                'identitystore:DescribeGroup'
              ],
              resources: ['*']
            })
          ]
        }),
        'iam-admin-access-mgmt-account': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'iam:*'
              ],
              resources: ['arn:aws:iam::790288377308:*']
            })
          ]
        }),
        'sns-publish': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['sns:Publish'],
              resources: [this.ssoOperationsNotificationsTopic.topicArn]
            })
          ]
        })
      }
    });
    addOpCfnTags(this.ssoLambdasRole);

    this.ssoVpcLambdasRole = new iam.Role(this, 'sso-vpc-lambdas-role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')],
      inlinePolicies: {
        'read-secret-from-secretsmgr': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['secretsmanager:GetSecretValue'],
              resources: [`arn:aws:secretsmanager:eu-central-1:790288377308:secret:${bitbucketBotUser}*`]
            })
          ]
        }),
        'read-account-list-from-bucket': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['s3:GetObject'],
              resources: ['arn:aws:s3:::op-account-data-production/account-list.json']
            })
          ]
        }),
        'read-write-sso-user-permissions-bucket': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['s3:*'],
              resources: ['arn:aws:s3:::op-sso-user-permissions/*']
            })
          ]
        }),
        'allow-ec2-egress-vpc': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'ec2:DescribeSecurityGroups',
                'ec2:DescribeSubnets',
                'ec2:DescribeNetworkInterfaces',
                'ec2:CreateNetworkInterface',
                'ec2:DescribeDhcpOptions',
                'ec2:DeleteNetworkInterface',
                'ec2:DescribeVpcs'
              ],
              resources: ['*']
            }),
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['ec2:CreateNetworkInterfacePermission'],
              resources: ['arn:aws:ec2:eu-central-1:790288377308:network-interface/*'],
              conditions: { StringLike: { 'ec2:AuthorizedService': 'codebuild.amazonaws.com' } }
            })
          ]
        }),
        'sso-admin-access': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'sso:List*',
                'sso:Describe*',
                'sso:ProvisionPermissionSet',
                'sso:CreateAccountAssignment',
                'sso:DeleteAccountAssignment',
                'identitystore:DescribeUser',
                'identitystore:ListUsers',
                'identitystore:ListGroups',
                'identitystore:DescribeGroup'
              ],
              resources: ['*']
            })
          ]
        }),
        'iam-admin-access-mgmt-account': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'iam:*'
              ],
              resources: ['arn:aws:iam::790288377308:*']
            })
          ]
        }),
        'sns-publish': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['sns:Publish'],
              resources: [this.ssoOperationsNotificationsTopic.topicArn]
            })
          ]
        })
      }
    });
    addOpCfnTags(this.ssoVpcLambdasRole);

    this.ssoValidatorLambda = new lambda.Function(this, 'sso-validator-lambda', {
      functionName: 'cfn-sso-validator',
      description: 'Lambda function to validate and resolve SSO permission change requests',
      code: lambda.Code.fromAsset('lambda/validator_lambda'),
      handler: 'handler.lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_9,
      memorySize: 128,
      timeout: Duration.seconds(60),
      retryAttempts: 0,
      role: this.ssoLambdasRole,
      environment: {
        SSO_INSTANCE_ARN: ssoInstanceArn,
        IDENTITY_STORE_ID: identityStoreId
      }
    });
    addOpCfnTags(this.ssoValidatorLambda);

    this.ssoAssignmentAndProvisionLambda = new lambda.Function(this, 'sso-assignment-and-provision-lambda', {
      functionName: 'cfn-sso-assignment-and-provision',
      description: 'Lambda function for doing account assignments and permission set provisioning',
      code: lambda.Code.fromAsset('lambda/assignment_and_provision_lambda'),
      handler: 'handler.lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_9,
      memorySize: 128,
      timeout: Duration.seconds(900),
      retryAttempts: 0,
      role: this.ssoLambdasRole,
      environment: {
        SSO_INSTANCE_ARN: ssoInstanceArn,
        IDENTITY_STORE_ID: identityStoreId
      }
    });
    addOpCfnTags(this.ssoAssignmentAndProvisionLambda);

    this.ssoErrorHandlingLambda = new lambda.Function(this, 'sso-error-handling-lambda', {
      functionName: 'cfn-sso-error-handling',
      description: 'Lambda function to catch SSO state machine errors and notify to Teams',
      code: lambda.Code.fromAsset('lambda/error_handling_lambda'),
      handler: 'handler.lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_9,
      memorySize: 128,
      timeout: Duration.seconds(30),
      retryAttempts: 1,
      role: this.ssoErrorHandlingLambdasRole,
      environment: {
        NOTIFICATIONS_TOPIC_ARN: this.ssoOperationsNotificationsTopic.topicArn
      }
    });
    addOpCfnTags(this.ssoErrorHandlingLambda);

    new lambda.EventInvokeConfig(this, 'sso-error-handling-lambda-event-invoke-config', {
      function: this.ssoErrorHandlingLambda,
      onFailure: new lambda_destinations.SnsDestination(this.ssoOperationsNotificationsTopic)
    });

    const importedVpc: ec2.IVpc = ec2.Vpc.fromLookup(this, 'imported-vpc', {
      tags: { 'aws:cloudformation:logical-id': 'VPC' },
      subnetGroupNameTag: 'SubnetGroup'
    });
    const importedApplicationSubnets = importedVpc.selectSubnets({
      subnetGroupName: 'application'
    });
    const BitbucketSg = ec2.SecurityGroup.fromSecurityGroupId(this, 'BB-SG', 'sg-099ff15abeea68d4f');
    const gitLayer = lambda.LayerVersion.fromLayerVersionArn(this, 'git-lambda-layer', 'arn:aws:lambda:eu-central-1:790288377308:layer:lambda-git:1');

    this.ssoCfnPullRequestLambda = new lambda.Function(this, 'cfn-sso-pull-req-creator-func', {
      functionName: 'cfn-sso-pull-req-creator-func',
      description: 'Lambda function to permissions create pull reqs',
      code: lambda.Code.fromAsset('lambda/pull_req_lambda'),
      handler: 'handler.lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_9,
      layers: [gitLayer],
      memorySize: 128,
      securityGroups: [BitbucketSg],
      vpc: importedVpc,
      vpcSubnets: importedApplicationSubnets,
      timeout: Duration.minutes(3),
      retryAttempts: 1,
      role: this.ssoVpcLambdasRole,
      environment: {
        IDENTITY_STORE_ID: identityStoreId,
        BB_USER: bitbucketBotUser
      }
    });
    addOpCfnTags(this.ssoCfnPullRequestLambda);

    this.accountDataPullRequestLambda = new lambda.Function(this, 'account-data-pr-creator-func', {
      functionName: 'cfn-account-data-pr-creator-func',
      description: 'Lambda function to account data pull reqs',
      code: lambda.Code.fromAsset('lambda/account_mod_lambda'),
      handler: 'handler.lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_9,
      layers: [gitLayer],
      memorySize: 128,
      securityGroups: [BitbucketSg],
      vpc: importedVpc,
      vpcSubnets: importedApplicationSubnets,
      timeout: Duration.minutes(3),
      retryAttempts: 1,
      role: this.ssoVpcLambdasRole,
      environment: {
        BB_USER: bitbucketBotUser
      }
    });
    addOpCfnTags(this.accountDataPullRequestLambda);

    const accPrincipals = opHubAccounts.map(opHubAccount => new iam.AccountPrincipal(opHubAccount));

    new iam.Role(this, 'sso-cfn-pullrequest-runner-role',
      {
        assumedBy: new iam.CompositePrincipal(...accPrincipals),
        inlinePolicies: {
          'invoke-pullreq-lambda': new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: ['lambda:invokefunction'],
                resources: [this.ssoCfnPullRequestLambda.functionArn, this.accountDataPullRequestLambda.functionArn]
              })
            ]
          })
        }
      });

    this.ssoStateMachineRole = new iam.Role(this, 'sso-state-machine-role', {
      assumedBy: new iam.ServicePrincipal('states.amazonaws.com'),
      inlinePolicies: {
        'invoke-lambda-functions': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['lambda:InvokeFunction'],
              resources: ['arn:aws:lambda:eu-central-1:790288377308:function:cfn-sso-*']
            })
          ]
        })
      }
    });
    addOpCfnTags(this.ssoStateMachineRole);

    const validateInput: tasks.LambdaInvoke = new tasks.LambdaInvoke(this, 'validation-step', {
      lambdaFunction: this.ssoValidatorLambda,
      payloadResponseOnly: true
    });

    const assignAndProvision: tasks.LambdaInvoke = new tasks.LambdaInvoke(this, 'apply-step', {
      lambdaFunction: this.ssoAssignmentAndProvisionLambda,
      payloadResponseOnly: true,
      retryOnServiceExceptions: true
    });

    const errorHandling: tasks.LambdaInvoke = new tasks.LambdaInvoke(this, 'error-handling-step', {
      lambdaFunction: this.ssoErrorHandlingLambda,
      payloadResponseOnly: true
    });

    const map: stepfunctions.Map = new stepfunctions.Map(this, 'Map', {
      maxConcurrency: 1,
      itemsPath: '$.chunked_account_list',
      parameters: {
        'account_list.$': '$$.Map.Item.Value',
        'principal.$': '$.principal',
        'permission_set.$': '$.permission_set',
        'permission_operation.$': '$.permission_operation'
      }
    }).itemProcessor(assignAndProvision);

    const stateMachineDefinitionChain = validateInput.addCatch(errorHandling).next(map.addCatch(errorHandling));

    this.ssoStateMachine = new stepfunctions.StateMachine(this, 'sso-state-machine', {
      definitionBody: stepfunctions.DefinitionBody.fromChainable(stateMachineDefinitionChain),
      role: this.ssoStateMachineRole
    });
    addOpCfnTags(this.ssoStateMachine);

    this.ssoStateMachineArn = new ssm.StringParameter(this, 'ssm-state-machine-arn', {
      description: 'CFN SSO State Machine ARN',
      parameterName: '/cloudfoundation/statemachine/sso/arn',
      stringValue: this.ssoStateMachine.stateMachineArn
    });
    addOpCfnTags(this.ssoStateMachineArn);

    const ssoUserPermissionsBucketName = 'op-sso-user-permissions';
    this.ssoUserPermissionsBucket = new s3.Bucket(this, 'sso-user-permissions-bucket', {
      bucketName: ssoUserPermissionsBucketName,
      versioned: true,
      accessControl: s3.BucketAccessControl.BUCKET_OWNER_FULL_CONTROL,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_PREFERRED
    });

    addOpCfnTags(this.ssoUserPermissionsBucket);

    this.ssoUserPermissionsLambda = new lambda.Function(this, 'sso-user-permissions-lambda', {
      functionName: 'cfn-sso-user-permissions',
      description: 'Lambda function retrive current user permissions from SSO',
      code: lambda.Code.fromAsset('lambda/user_permissions_lambda'),
      handler: 'handler.lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_9,
      memorySize: 128,
      timeout: Duration.seconds(900),
      role: this.ssoLambdasRole,
      environment: {
        SSO_INSTANCE_ARN: ssoInstanceArn,
        IDENTITY_STORE_ID: identityStoreId,
        SSO_USER_PERMISSIONS_BUCKET: ssoUserPermissionsBucketName
      }
    });
    addOpCfnTags(this.ssoUserPermissionsLambda);

    new lambda.EventInvokeConfig(this, 'sso-user-permissions-lambda-event-invoke-config', {
      function: this.ssoUserPermissionsLambda,
      onFailure: new lambda_destinations.LambdaDestination(this.ssoErrorHandlingLambda)
    });

    this.ssoUserPermissionsScheduleEvent = new events.Rule(this, 'sso-user-permissions-schedule-event', {
      schedule: events.Schedule.cron({ minute: '0', hour: '4' }),
      targets: [new events_targets.LambdaFunction(this.ssoUserPermissionsLambda, { retryAttempts: 2 })]
    });
    addOpCfnTags(this.ssoUserPermissionsScheduleEvent);
  }
}
