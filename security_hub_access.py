import json
import csv
import boto3

iam = boto3.client('iam')

sts = boto3.client('sts')

def check_policy_for_securityhub(policy_document):
    for statement in policy_document['Statement']:
        if isinstance(statement, dict):
            if 'Action' in statement:
                if isinstance(statement['Action'], list):
                    for action in statement['Action']:
                        if 'securityhub' in action:
                            return "securityhub"
                        elif action == '*':
                            return "*"
                        elif 'iam:*' in action:
                            return "iam:*"
                else:
                    if 'securityhub' in statement['Action']:
                        return "securityhub"
                    elif statement['Action'] == '*':
                        return "*"
                    elif 'iam:*' in statement['Action']:
                        return "iam:*"
    return None

# Call the STS service to get the account ID
account_id = sts.get_caller_identity()['Account']

# Prepare a CSV file to write the results
with open(f'{account_id}_security_hub_access.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Type", "Name", "IsSSORole", "Access"])

    # List all roles
    roles = iam.list_roles()['Roles']

    # For each role, check if it has Security Hub access
    for role in roles:
        role_name = role['RoleName']

        # Check if it's an SSO role
        is_sso_role = role['Path'].startswith('/aws-reserved/sso.amazonaws.com/')

        # Get role's attached and inline policies
        attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        inline_policies = iam.list_role_policies(RoleName=role_name)['PolicyNames']

        # Check each attached policy to see if it grants Security Hub access
        for policy in attached_policies:
            policy_details = iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']
            if 'DefaultVersionId' in policy_details:
                policy_version = iam.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId=policy_details['DefaultVersionId']
                )['PolicyVersion']

                # Check if the policy document grants Security Hub access
                access = check_policy_for_securityhub(policy_version['Document'])  
                if access:
                    writer.writerow(["Role", role_name, is_sso_role, access])  

        # Check each inline policy to see if it grants Security Hub access
        for policy_name in inline_policies:
            policy_document = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']

            access = check_policy_for_securityhub(policy_document)  
            if access:
                writer.writerow(["Role", role_name, is_sso_role, access])  

    # For each user, list policies and check for Security Hub access
    users = iam.list_users()['Users']
    for user in users:
        user_name = user['UserName']

        # Get user's attached and inline policies
        attached_policies = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
        inline_policies = iam.list_user_policies(UserName=user_name)['PolicyNames']

        # Check each attached policy to see if it grants Security Hub access
        for policy in attached_policies:
            if 'DefaultVersionId' in policy:
                policy_version = iam.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy['DefaultVersionId'])['PolicyVersion']

                access = check_policy_for_securityhub(policy_version['Document'])  
                if access:
                    writer.writerow(["User", user_name, "False", access])  

        # Check each inline policy to see if it grants Security Hub access
        for policy_name in inline_policies:
            policy_document = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']

            access = check_policy_for_securityhub(policy_document)  
            if access:
                writer.writerow(["User", user_name, "False", access])  