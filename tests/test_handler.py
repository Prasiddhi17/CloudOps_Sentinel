
import importlib
import sys
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def aws_resources(monkeypatch):
    # Start simulated AWS services
    aws_mock = mock_aws()
    aws_mock.start()

    # Set dummy AWS credentials for local testing
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    table_name = "TestSecurityIncidents"

    # Create a simulated DynamoDB table
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

    table = dynamodb.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "event_id", "KeyType": "HASH"}
        ],
        AttributeDefinitions=[
            {"AttributeName": "event_id", "AttributeType": "S"}
        ],
        BillingMode="PAY_PER_REQUEST"
    )

    # Create a simulated SNS topic
    sns = boto3.client("sns", region_name="us-east-1")
    topic_arn = sns.create_topic(
        Name="TestSecurityAlerts"
    )["TopicArn"]

    monkeypatch.setenv("TABLE_NAME", table_name)
    monkeypatch.setenv("TOPIC_ARN", topic_arn)

    # Make the lambda folder importable
    lambda_path = str(
        Path(__file__).resolve().parents[1] / "lambda"
    )

    if lambda_path not in sys.path:
        sys.path.insert(0, lambda_path)

    # Import/reload handler after setting up mock AWS
    import handler
    handler = importlib.reload(handler)

    yield handler, table, topic_arn

    aws_mock.stop()


def sample_event():
    return {
        "id": "test-event-001",
        "detail": {
            "eventID": "test-event-001",
            "eventName": "ConsoleLogin",
            "eventTime": "2026-11-26T10:00:00Z",
            "sourceIPAddress": "192.0.2.10",
            "userIdentity": {
                "userName": "test-user"
            }
        }
    }


def test_security_event_is_saved(aws_resources):
    handler, table, topic_arn = aws_resources

    with patch.object(
        handler.sns,
        "publish",
        wraps=handler.sns.publish
    ) as publish_mock:

        result = handler.lambda_handler(sample_event(), None)

        # Lambda should report success
        assert result["statusCode"] == 200

        # Incident should be saved in DynamoDB
        saved_item = table.get_item(
            Key={"event_id": "test-event-001"}
        )["Item"]

        assert saved_item["event_name"] == "ConsoleLogin"
        assert saved_item["severity"] == "HIGH"
        assert saved_item["status"] == "DETECTED"

        # SNS should receive one alert
        publish_mock.assert_called_once()

        assert publish_mock.call_args.kwargs["TopicArn"] == topic_arn


def test_duplicate_event_is_ignored(aws_resources):
    handler, table, topic_arn = aws_resources

    with patch.object(
        handler.sns,
        "publish",
        wraps=handler.sns.publish
    ) as publish_mock:

        first_result = handler.lambda_handler(sample_event(), None)
        second_result = handler.lambda_handler(sample_event(), None)

        assert first_result["statusCode"] == 200

        assert second_result["message"] == "Duplicate event ignored"

        # Only the first event should generate an alert
        publish_mock.assert_called_once()


def test_missing_event_id_raises_error(aws_resources):
    handler, table, topic_arn = aws_resources

    invalid_event = {
        "detail": {
            "eventName": "ConsoleLogin"
        }
    }

    with pytest.raises(ValueError, match="Event ID is missing"):
        handler.lambda_handler(invalid_event, None)
