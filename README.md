# CloudOps Sentinel — AWS Security Monitoring and Incident Alerting

## Project Overview

CloudOps Sentinel is an AWS-based security monitoring and incident alerting platform designed to detect suspicious account activity and notify administrators.

The project uses AWS services and Infrastructure as Code (Terraform) to automate security event processing.

## Architecture

1. AWS CloudTrail records account activity.
2. Amazon EventBridge detects selected security events.
3. AWS Lambda processes security events using Python.
4. Amazon DynamoDB stores incident records.
5. Amazon SNS sends email notifications.
6. Amazon CloudWatch stores Lambda execution logs.
7. Amazon S3 stores CloudTrail audit logs.

## Technologies Used

- Amazon Web Services (AWS)
- AWS Lambda
- AWS CloudTrail
- Amazon EventBridge
- Amazon DynamoDB
- Amazon SNS
- Amazon S3
- Amazon CloudWatch
- Python
- Terraform
- Git and GitHub
- Pytest and Moto

## Project Features

- Detects failed AWS console sign-in events.
- Monitors selected sensitive IAM changes.
- Processes security events using Python Lambda.
- Stores incident details in DynamoDB.
- Sends security alerts using SNS.
- Uses Terraform to define AWS infrastructure.
- Includes local automated tests using pytest and Moto.

## Project Structure

```text
cloudops-sentinel/
├── lambda/
├── tests/
├── events/
├── terraform/
├── requirements-dev.txt
├── .gitignore
└── README.md
```

## Local Testing

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Run tests:

```bash
python -m pytest -v
```

## Infrastructure Deployment

Terraform configuration is maintained in the `terraform/` directory.

Review the Terraform plan before deployment:

```bash
cd terraform
terraform init
terraform validate
terraform plan
```

Review AWS costs and account eligibility before applying infrastructure.

## Security Considerations

- Uses IAM permissions scoped to required project resources.
- Does not store AWS credentials in source code.
- Excludes Terraform state and personal configuration from Git.
- Uses simulated AWS services for local tests.

## Project Status

Local Python tests and Terraform validation have been completed.

AWS deployment and live integration testing should be documented only after they have actually been completed.

## Author

CloudOps Sentinel — AWS Cloud Security and DevOps Portfolio Project
CloudOps Sentinel — AWS Cloud Security and DevOps Portfolio Project
