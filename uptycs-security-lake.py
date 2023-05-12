#####
#
# Uptycs Security Lake Log Source Provider
# Setup script
# Requires boto3 > 1.26.112 for new securitylake api
#
# The script
# 1) Creates a lake administrator role which can be assumed by lamgda
# 2) Adds the role to the security lake admins under lakeformation
# 3) Grants the role CreateTable permissions on the security lake db
#
#####

import boto3
import argparse
import json
import uuid
import botocore.exceptions
import sys
import time
from distutils.version import LooseVersion

#
# Some constants which may be modified post launch
#
STACK_NAME = 'Uptycs-Security-Lake'
TEMPLATE_FILENAME = 'uptycs_log_source_template.yaml'
REQUIRED_BOTO3_VERSION = '1.26.110'
CUSTOM_SOURCE_PREFIX = "UPTYCS"
UPTYCS_ROLE_NAME = 'mysecuritylake-writer'
LOCAL_ROLE_NAME = 'UptycsSecLakeWriteAccess'
UPTYCS_ACCOUNT_ID = '235115201540'
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:048950004707:uptycs-securitylake-registration'
UPTYCS_IAM_POLICY_NAME = 'UptycsSecurityLakeBucketAccessPolicy'
aws_region = 'us-east-1'
#
# Setup Boto3 clients
#
sl_client = boto3.client('securitylake', region_name=aws_region)
sns_client = boto3.client('sns', region_name=aws_region)
iam_client = boto3.client('iam')
dl_client = boto3.client('lakeformation', region_name=aws_region)
cf_client = boto3.client('cloudformation', region_name=aws_region)

#
# Policies required for Lakeformation role used by lambda
#
lambda_assume_role_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "lambda",
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    ]
}
dl_admin_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "securitylake:*",
                "organizations:DescribeOrganization",
                "organizations:ListDelegatedServicesForAccount",
                "iam:ListRoles"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:PassedToService": [
                        "securitylake.amazonaws.com",
                        "lambda.amazonaws.com",
                        "s3.amazonaws.com"
                    ]
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "arn:aws:iam::*:role/aws-service-role/securitylake.amazonaws.com/AWSServiceRoleForSecurityLake",
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": "securitylake.amazonaws.com"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreateRole",
            "Resource": [
                "arn:aws:iam::*:role/service-role/AmazonSecurityLakeMetaStoreManager",
                "arn:aws:iam::*:role/service-role/AmazonSecurityLakeS3ReplicationRole"
            ]
        },
        {
            "Effect": "Allow",
            "Action": "iam:AttachRolePolicy",
            "Resource": [
                "arn:aws:iam::*:role/service-role/AmazonSecurityLakeMetaStoreManager",
                "arn:aws:iam::*:role/service-role/AmazonSecurityLakeS3ReplicationRole"
            ],
            "Condition": {
                "ArnEquals": {
                    "iam:PolicyARN": [
                        "arn:aws:iam::*:policy/service-role/AmazonSecurityLakeMetaStoreManagerRolePolicy",
                        "arn:aws:iam::*:policy/service-role/AmazonSecurityLakeS3ReplicationRolePolicy"
                    ]
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreatePolicy",
            "Resource": [
                "arn:aws:iam::*:policy/service-role/AmazonSecurityLakeMetaStoreManagerRolePolicy",
                "arn:aws:iam::*:policy/service-role/AmazonSecurityLakeS3ReplicationRolePolicy"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:CreateBucket",
                "s3:PutBucketPolicy",
                "s3:PutBucketPublicAccessBlock",
                "s3:PutBucketNotification",
                "s3:PutBucketTagging",
                "s3:PutEncryptionConfiguration",
                "s3:PutBucketVersioning",
                "s3:PutReplicationConfiguration",
                "s3:PutLifecycleConfiguration",
                "lambda:CreateFunction",
                "lambda:CreateEventSourceMapping",
                "glue:CreateDatabase",
                "glue:GetDatabase",
                "glue:CreateTable",
                "lakeformation:GrantPermissions",
                "lakeformation:PutDatalakeSettings",
                "lakeformation:GetDatalakeSettings",
                "events:PutTargets",
                "events:PutRule",
                "sqs:CreateQueue",
                "sqs:SetQueueAttributes",
                "iam:GetRole",
                "sqs:GetQueueURL",
                "sqs:AddPermission",
                "sqs:GetQueueAttributes",
                "kms:DescribeKey",
                "kms:CreateGrant"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringEquals": {
                    "aws:CalledVia": [
                        "securitylake.amazonaws.com"
                    ]
                }
            }
        }
    ]
}


def create_iam_policy(policy_name: str , permisssions_policy: str) -> bool:
    """
    Args:
        policy_name (str): The name of the policy
        permisssions_policy (str): The permissions policy to assign to the role

    Returns (str): The policy Arn
    """

    account_id = get_account()
    policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
    # Create the policy
    try:
        print(f'Checking for policy {policy_arn}\n')
        response = iam_client.get_policy(PolicyArn=policy_arn)
        # If the policy exists, skip creation
        print(f"Policy {policy_arn} exists already....Skipping Creation\n")
        return policy_arn
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchEntity':
            print(f'Policy {policy_arn} does not exist....Creating\n')
            # If the policy does not exist, create the policy
            print(f"Creating Policy {policy_arn}:")
            # Create the policy here
            response = iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=permisssions_policy
            )
            policy_arn = response['Policy']['Arn']
            print(f'Policy {policy_arn} created\n')
            return policy_arn
    except Exception as error:
        print('Error checking IAM policy')


def create_iam_role(role_name: str, permissions_policy_arn: str, assume_role_policy_doc: str):
    """

    Args:
        role_name (str): The role name
        permissions_policy_arn (str): The arn of the permissions policy to attach to the role
        assume_role_policy_doc (str): The policy to apply as a json format string

    Returns (str): Role Arn
    """
    try:
        # First check if the role exists
        print(f'Checking for role {role_name}\n')
        response = iam_client.get_role(RoleName=role_name)
        print(f'Role {role_name} exists already....Skipping Creation\n')
        return response['Role']['Arn']
    except botocore.exceptions.ClientError as error:
        # Given the exception assume the role does not exist and create it
        print(f'Role {role_name} does not exist....Creating\n')
        if error.response['Error']['Code'] == 'NoSuchEntity':
            response = iam_client.create_role(
                RoleName=role_name,
                Description="Uptycs Role for Writing to Security Lake Bucket",
                AssumeRolePolicyDocument=json.dumps(assume_role_policy_doc)
            )
            print(
                f"Role {LOCAL_ROLE_NAME} created successfully with RoleId: {response['Role']['RoleId']}")
            if response['Role']['Arn']:
                attach_policy(role_name, dl_admin_policy_arn)
                attach_policy(role_name,
                              'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
                attach_policy(role_name,
                              'arn:aws:iam::aws:policy/AdministratorAccess')
                time.sleep(5)
                # Wait until the role has been created and replicated internally by AWS to all
                # regions. Without the delay subsequent api calls may fail due to role not being
                # available
            return response['Role']['Arn']

        elif error == 'EntityAlreadyExists':
            print(f'Role {LOCAL_ROLE_NAME} already exists')
        else:
            print(f'Error {error} creating role {LOCAL_ROLE_NAME}')
    except Exception as error:
        print(error)

    # Attach the trust policy to the uptycssecuritylakewriter role


def attach_policy(role_name: str, policy_arn: str) -> bool:
    """

    Args:
        role_name (str): The role name that the policy will be attached to
        policy_arn (str): The Arn of the policy attached

    Returns: bool for success or failure True = Success

    """
    try:
        print(f'Attaching policy {policy_arn} to role {role_name}\n')
        response = iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print(f'Attached policy arn {policy_arn} to role {role_name}\n')
            print(f'Successfully attached policy {policy_arn} to role {role_name}\n')
            return True
        else:
            print(f'Failed to attach policy {policy_arn} to role {role_name}\n')
            return
    except Exception as error:
        print(error)


def gen_external_id():
    """

    Returns: A random string in UUID v4 format


    """
    return str(uuid.uuid4())


def get_account():
    """

    Returns: The AWS AccountID this script is executing in

    """
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()["Account"]
    return account_id


def update_grant_permissions(lambda_role_arn: str, db: str, account_id: str):
    """
    Adds CREATE_TABLE permissions to a lakeformation db for a given role arn
    Args:
        lambda_role_arn (str): The Arn of the role that will be granted permissions
        db (str): The name of the lakeformation db that the permissions will be granted on
        account_id (str): The AWS AccountID

    Returns:

    """
    try:
        response = dl_client.grant_permissions(

            Principal={
                'DataLakePrincipalIdentifier': lambda_role_arn
            },

            Resource={
                'Database': {
                    'CatalogId': account_id,
                    'Name': db
                }
            },
            Permissions=['CREATE_TABLE'],
            PermissionsWithGrantOption=[],
        )
        return response
    except botocore.exceptions.ClientError as error:
        raise error
    except Exception as error:
        print(error)
        return


def get_security_lake_db(region: str) ->str:
    """
    Returns the name of the amazon security lake db in a given region
    Assumes the security lake db will have a prefix amazon_security_lake
    Args:
        region (str):

    Returns (str): The nane of the security lakte db

    """
    gl_client = boto3.client('glue', region_name='region')
    response = gl_client.get_databases()
    db_list = response['DatabaseList']
    for db in db_list:
        if 'amazon_security_lake' in db['Name']:
            return db['Name']


# def _parse_template(template):
#     with open(template) as template_fileobj:
#         template_data = template_fileobj.read()
#     # cf_client.validate_template(TemplateBody=template_data)
#     return template_data

def get_dl_admins() -> dict:
    """

    Returns: A dict of existing db administrators

    """
    try:
        response = dl_client.get_data_lake_settings()
        dl_admins_list = response['DataLakeSettings']['DataLakeAdmins']
        return dl_admins_list
    except botocore.exceptions.ClientError as error:
        print(error)
    except Exception as error:
        print(f'Error retrieving LakeFormation administrators {error}')

def update_dl_admins(existing_principles: dict, role_arn: str):
    """
    Adds a new db admin if it does not currently exist

    Args:
        existing_principles (dict):
        role_arn (str):

    Returns: API response

    """
    try:

        lambda_admin_principle = {
            "DataLakePrincipalIdentifier": role_arn
        }
        print(f'Adding role {role_arn} to DataLake Admins\n')
        existing_principles.append(lambda_admin_principle)
        response = dl_client.put_data_lake_settings(
            DataLakeSettings={
                'DataLakeAdmins': dl_admins_list
            }
        )
        return response
    except Exception as error:
        raise error

def get_current_region():
    """

    Returns: The curent AWS region

    """
    session = boto3.session.Session()
    region = session.region_name
    return region


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Create Uptycs Security Lake Custom log source'
    )
    parser.add_argument('-c', '--uptycs_customer_id', required=True,
                        help='REQUIRED: Your Uptycs customer customer_id ')
    parser.add_argument('-d', '--uptycs_domain', required=True,
                        help='REQUIRED: Your Uptycs customer domain ')
    parser.add_argument('-b', '--staging_bucket', required=True,
                        help='REQUIRED: The bucket containing the layer and cloudformation '
                             'template ')
    parser.add_argument('-l', '--security_lake_bucket', required=True,
                        help='REQUIRED: The name of the S3 bucket created by security lake in '
                             'this region. Normally aws-security-lake-xxxxxx')
    parser.add_argument('-g', '--glue_arn', default=None,
                        help='REQUIRED: IAM role that permits the source to write data to the correct location in the data lake')
    args = parser.parse_args()

    uptycs_customer_id = args.uptycs_customer_id
    uptycs_domain = args.uptycs_domain
    security_lake_bucket = args.security_lake_bucket
    glue_arn = args.glue_arn
    aws_region='us-east-1'
    # aws_region = get_current_region()

    if LooseVersion(boto3.__version__) < LooseVersion(REQUIRED_BOTO3_VERSION):
        print(f'Boto3 Version {REQUIRED_BOTO3_VERSION} or higher required')
        sys.exit(1)

    try:
        print('\n### Step 1: Create the lakeformation administration role ###\n')
        dl_admin_policy_arn = create_iam_policy('UptycsSecurityLakeAdminPolicy', json.dumps(
            dl_admin_policy))
        # Create security lake admin policy

        if dl_admin_policy_arn:
            lambda_role_arn = create_iam_role('UptycsSecurityLakeAdminLambdaRole', dl_admin_policy_arn,
                                              lambda_assume_role_policy)
            # Wait for role to create and replicate to regions
            time.sleep(5)
        print('\n### Step 2: Retrieve existing Datalake administrators ###\n')
        dl_admins_list = get_dl_admins()
        print(f'The Existing administrator list is {dl_admins_list}\n')
        update_dl_admins(dl_admins_list, lambda_role_arn)
        response = dl_client.get_data_lake_settings()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            new_admin_list = response['DataLakeSettings']['DataLakeAdmins']
            print(f'New administrator list is {new_admin_list}\n')
        print(f'\n### Step 3: Updating permissions ###\n')
        print(f'Adding table create permissions for role {lambda_role_arn}\n')
        # db = get_security_lake_db(aws_region)
        db_region_name = aws_region.replace('-', '_')
        account_id = get_account()
        secuirty_lake_db_name = f'amazon_security_lake_glue_db_{db_region_name}'
        update_grant_permissions(lambda_role_arn, secuirty_lake_db_name, account_id)
    except Exception as error:
        print(error.response['Error']['Message'])
        print('\n### Failed to create required role prerequisites ....exiting ###\n')
        sys.exit(1)

    print(gen_external_id())
    print(f'\n### Step 4: Creating Cloudformation Stack to manage Uptycs custom log sources ###\n')


    parameter_data = [
        {
            'ParameterKey': 'GlueArn',
            'ParameterValue': args.glue_arn,
        },
        {
            'ParameterKey': 'UptycsSecurityLakeAdminLambdaRoleArn',
            'ParameterValue': lambda_role_arn,
        },
        {
            'ParameterKey': 'LayerBucket',
            'ParameterValue': args.staging_bucket,
        },
        {
            'ParameterKey': 'UptycsCustomerId',
            'ParameterValue': args.uptycs_customer_id,
        },
        {
            'ParameterKey': 'SecurityLakeS3bucket',
            'ParameterValue': args.security_lake_bucket,
        },
        {
            'ParameterKey': 'UptycsDomain',
            'ParameterValue': args.uptycs_domain,
        },
        {
            'ParameterKey': 'UptycsAccountId',
            'ParameterValue': UPTYCS_ACCOUNT_ID,
        }
    ]

    try:
        with open(TEMPLATE_FILENAME, 'r') as file:
            template_body = file.read()
        # template_object = _parse_template(TEMPLATE_FILENAME)
        params = parameter_data

        response = cf_client.create_stack(
            StackName=STACK_NAME,
            TemplateBody=template_body,
            Parameters=params,
            DisableRollback=True,
            TimeoutInMinutes=5,
            Capabilities=[
                'CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'
            ]
        )
    except Exception as error:
        print(error)












