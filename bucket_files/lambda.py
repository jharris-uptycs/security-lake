#
# Lambda function to create Uptycs Custom Security Lake log source
#
import boto3
import logging
import json
import cfnresponse
import threading
import uuid
import botocore.exceptions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CUSTOM_SOURCE_PREFIX = "UPTYCS"
client = boto3.client('securitylake', region_name='us-east-1')
sns_client = boto3.client('sns', region_name='us-east-1')
iam_client = boto3.client('iam')
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:235115201540:uptycs-test-security-lake-integration-protectum:db433683-292f-4a1c-87be-b192675970fe'


def gen_external_id():
    return str(uuid.uuid4())


def get_bucket_arn(region):
    data_lake_data = client.get_datalake()
    return (data_lake_data['configurations'][region]['s3BucketArn'])


def publish_to_sns(msg):
    try:
        message_str = json.dumps({'default': json.dumps(msg)})
        response = sns_client.publish(
            TargetArn=SNS_TOPIC_ARN,
            Message=message_str,
            MessageStructure='json'
        )
        print(f'sns response {response}')
    except Exception as error:
        print(error)


def create(event_class, log_provider_account_id, glue_arn):
    try:
        custom_source_name = f'{CUSTOM_SOURCE_PREFIX}_{event_class}'
        response = client.create_custom_log_source(
            customSourceName=custom_source_name,
            eventClass=event_class,
            glueInvocationRoleArn=glue_arn,
            logProviderAccountId=log_provider_account_id
        )
        logger.info('Created custom log source {}'.format(custom_source_name))
        return response
    except botocore.exceptions.ClientError as error:
        print(error)
        logger.info('Response to create {}'.format(error))
    except Exception as error:
        logger.info('Response to create  {}'.format(error))


def delete(event_class):
    try:
        custom_source_name = f'{CUSTOM_SOURCE_PREFIX}_{event_class}'
        response = client.delete_custom_log_source(
            customSourceName=custom_source_name)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            logger.info('Deleted log source {}'.format(custom_source_name))
            return response
    except botocore.exceptions.ClientError as clienterror:
        logger.info('Response to create {}'.format(clienterror))
        print(clienterror)
        return False
    except Exception as error:
        logger.info('Response to delete  {}'.format(error))
        return False


def timeout(event, context):
    logging.error("Execution is about to time out, sending failure response to CloudFormation")
    cfnresponse.send(event, context, cfnresponse.FAILED, {}, None)


def update_assume_role_policy_for_uptycs(uptycs_account_id, role_name, external_id):
    logger.info('Updating role')
    print('Updating role')
    policy = {
        "Effect": "Allow",
        "Principal": {
            "AWS": f"arn:aws:iam::{uptycs_account_id}:root"
        },
        "Action": "sts:AssumeRole",
        "Condition": {
            "StringEquals": {
                "sts:ExternalId": external_id
            }
        }
    }

    try:
        # Get the existing AssumeRolePolicyDocument for the role
        new_doc = []
        response = iam_client.get_role(RoleName=role_name)
        print(f'existing role {response}')
        logger.info('Existing role {}'.format(role_name))
        print('Existing role type{}'.format(type(response)))
        assume_role_policy_document = response['Role']['AssumeRolePolicyDocument']
        print('assume_role_policy_document type {}'.format(type(assume_role_policy_document)))
        new_doc.append(assume_role_policy_document['Statement'][0])
        new_doc.append(policy)
        pol_doc = {"Version": "2012-10-17",
                   "Statement": new_doc
                   }

        print('new_doc {}'.format(pol_doc))
        # # Append the new policy statement to the existing AssumeRolePolicyDocument
        pol_str = json.dumps(pol_doc)
        print(pol_str)
        response = iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=pol_str
        )
    except Exception as error:
        logger.info('Error {} updating role {} for Uptycs access'.format(error, role_name))


def handler(event, context):
    logger.info(event)
    # Send response before timeout
    # timer = threading.Timer((context.get_remaining_time_in_millis()
    # / 1000.00) - 0.5, timeout, args=[event, context])
    # timer.start()
    status = cfnresponse.SUCCESS
    event_class_list = ["FILE_SYSTEM_ACTIVITY"]
    aws_region = event['ResourceProperties']['aws_region']
    uptycs_account_id = event['ResourceProperties']['uptycs_account_id']
    assume_role_arn = event['ResourceProperties']['assume_role_arn']
    assume_role_external_id = gen_external_id()
    glue_arn = event['ResourceProperties']['glue_arn']
    uptycs_customer_id = event['ResourceProperties']['uptycs_customer_id']
    uptycs_domain = event['ResourceProperties']['uptycs_domain']

    if event['RequestType'] == 'Create':
        try:
            for event_class in event_class_list:
                event_create_data = create(event_class, uptycs_account_id, glue_arn)
                if event_create_data['ResponseMetadata']['HTTPStatusCode'] == 200:
                    logger.info('Event create data {}'.format(event_create_data))
                    bucket_arn = get_bucket_arn(aws_region)
                    message = {
                        "bucket_arn": bucket_arn,
                        "customDataLocation": event_create_data["customDataLocation"],
                        "glueCrawlerName": event_create_data["glueCrawlerName"],
                        "glueDatabaseName": event_create_data["glueDatabaseName"],
                        "glueTableName": event_create_data["glueTableName"],
                        "logProviderAccessRoleArn": event_create_data['logProviderAccessRoleArn'],
                        "assume_role_external_id": assume_role_external_id,
                        "assume_role_arn": assume_role_arn,
                        "uptycs_domain": uptycs_domain
                    }
                    parts = event_create_data['logProviderAccessRoleArn'].split(':')

                    # Get the last part of the resulting list and split it using the forward slash as the delimiter
                    role_parts = parts[-1].split('/')
                    # Get the last element of the resulting list, which is the role name
                    access_role_name = role_parts[-1]
                    # update_assume_role_policy_for_uptycs(uptycs_account_id, access_role_name, assume_role_external_id)
                    mesg = json.dumps(message)
                    publish_to_sns(mesg)
        except Exception as error:
            logging.error("Exception: {}".format(error))
            status = cfnresponse.FAILED
        finally:
            #   timer.cancel()
            cfnresponse.send(event, context, status, {}, None)

    elif event['RequestType'] == 'Delete':
        try:
            for event_class in event_class_list:
                delete(event_class)
                print('Deleted custom log source')
        except Exception as error:
            logger.error('Exiting due to client error')
        finally:
            #   timer.cancel()
            cfnresponse.send(event, context, status, {}, None)