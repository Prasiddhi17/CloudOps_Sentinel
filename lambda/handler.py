
import os
import json
import boto3

from botocore.exceptions import ClientError


# STEP 1: Connect to AWS services

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")


# STEP 2: Get environment variables

table = dynamodb.Table(os.environ["TABLE_NAME"])

topic_arn = os.environ["TOPIC_ARN"]


# STEP 3: Main Lambda function

def lambda_handler(event, context):

    print("Received security event:", json.dumps(event))

    # STEP 4: Extract CloudTrail event details

    detail = event.get("detail", {})

    event_id = detail.get(
        "eventID",
        event.get("id")
    )

    if not event_id:
        raise ValueError("Event ID is missing")

    identity = detail.get("userIdentity", {})

    incident = {
        "event_id": event_id,
        "event_name": detail.get("eventName", "Unknown"),
        "event_time": detail.get("eventTime", ""),
        "source_ip": detail.get("sourceIPAddress", "Unknown"),
        "user": identity.get("userName", "Unknown"),
        "severity": "HIGH",
        "status": "DETECTED"
    }

    # STEP 5: Store incident in DynamoDB

    try:

        table.put_item(
            Item=incident,
            ConditionExpression="attribute_not_exists(event_id)"
        )

        print("Incident saved successfully")

    except ClientError as error:

        error_code = error.response["Error"]["Code"]

        if error_code == "ConditionalCheckFailedException":

            print("Duplicate event detected")

            return {
                "statusCode": 200,
                "message": "Duplicate event ignored"
            }

        raise

    # STEP 6: Send notification using SNS

    message = json.dumps(incident, indent=2)

    sns.publish(
        TopicArn=topic_arn,
        Subject="AWS Security Alert",
        Message=message
    )

    print("Security alert sent successfully")

    # STEP 7: Return response

    return {
        "statusCode": 200,
        "message": "Security incident processed",
        "incident": incident
    }
