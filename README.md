# Boto3 Scripts

This repository contains a collection of useful scripts that utilize the Boto3 library to interact with AWS services.

## Scripts

### Hyperplane ENI Finder (`hyperplane_eni_finder.py`)

This script finds all Hyperplane Elastic Network Interfaces (ENIs) in use across the entire AWS account. It's not limited to just AWS Lambda functions using Hyperplane ENIs, but covers all services. Originally developed by Jiten P. of AWS Support and adapted by ivica-k.

### Identify KMS Stressors (`identify_stressors.py`)

This script searches AWS CloudTrail for AWS Key Management Service (KMS) decrypt actions over the last 24 hours. It identifies the top 10 users or services based on the number of decrypt events, which can help in identifying potential stressors or unusual activity. This can be retrofit to a variety of services and events. Warning: This can time out with too much data.

### Security Hub Access (`security_hub_access.py`)

This script identifies AWS IAM policies, roles, and AWS SSO groups with access to AWS Security Hub. This can be useful for auditing access to Security Hub and ensuring that only authorized entities have access.