import boto3
import csv
from collections import defaultdict
from datetime import datetime, timedelta

# Initialize the boto3 client
client = boto3.client('cloudtrail')

# Calculate the start and end times for the last 24 hours
end_time = datetime.now()
start_time = end_time - timedelta(hours=24)

# Initialize usage_data
usage_data = defaultdict(int)

# Get the decrypt events related to KMS from the last 24 hours
paginator = client.get_paginator('lookup_events')
for response in paginator.paginate(
    LookupAttributes=[
        {
            'AttributeKey': 'EventSource',
            'AttributeValue': 'kms.amazonaws.com'
        },
        {
            'AttributeKey': 'EventName',
            'AttributeValue': 'Decrypt'
        },
    ],
    StartTime=start_time,
    EndTime=end_time
    ):
    # Extract the username/service name and count the occurrences
    for event in response['Events']:
        if 'userIdentity' in event and 'userName' in event['userIdentity']:
            username = event['userIdentity']['userName']
        elif 'invokedBy' in event:
            username = event['invokedBy']
        else:
            username = 'Unknown'
        usage_data[username] += 1

# Sort the usage data and get the top 10
top_10 = sorted(usage_data.items(), key=lambda item: item[1], reverse=True)[:10]

# Write the data to a CSV file
with open('kms_usage.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Username", "KMS Decrypt Events"])
    writer.writerows(top_10)