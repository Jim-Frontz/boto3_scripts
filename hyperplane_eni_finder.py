# Originally developed by Jiten P. of AWS Support
# adapted by ivica-k
import boto3
import argparse


COUNT_ENIS = 0
COUNT_HENIS = 0
COUNT_HENIS_LAMBDA = 0

HENI_IDS_LAMBDA = []
HENI_IDS = []

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action="store_true", help="show HENI IDs")
parser.add_argument(
    "-r", "--region", default="us-west-2", help="name of the AWS region to search in"
)
args = parser.parse_args()

ec2_client = boto3.client("ec2", region_name=args.region)
response = ec2_client.describe_network_interfaces()

for interface in response["NetworkInterfaces"]:
    if "Attachment" in interface:
        eni_id = interface.get("Attachment").get("AttachmentId")
        COUNT_ENIS += 1

        if "ela-attach" in eni_id:
            COUNT_HENIS += 1
            HENI_IDS.append(interface.get("NetworkInterfaceId"))

        # check if the the attachment id has "ela-attach" in the it and if the "interfaceType" is Lambda.
        if "ela-attach" in eni_id and "lambda" in interface.get("InterfaceType"):
            COUNT_HENIS_LAMBDA += 1
            HENI_IDS_LAMBDA.append(interface.get("NetworkInterfaceId"))

print(f"Total number of ENIs: {COUNT_ENIS}")
print(f"Total number of hyperplane ENIs: {COUNT_HENIS}")
print(f"Total number of hyperplane ENIs used by Lambdas: {COUNT_HENIS_LAMBDA}")

if args.verbose:
    print(f"The list of hyperplane ENIs: {HENI_IDS}")
    print(f"The list of hyperplane ENIs associated with Lambdas: {HENI_IDS_LAMBDA}")