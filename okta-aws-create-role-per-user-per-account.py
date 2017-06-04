import boto3
import json
import requests
import yaml

# Open account_name session(I created credentials file with all my accounts)
def config_var(config_file_path):
    with open(config_file_path) as config:
        conf_vars = yaml.load(config.read())
        return  conf_vars

conf_vars = config_var('/home/yuvalm-pcu/Documents/scripts/okta-aws-config.yaml')
accounts = conf_vars['accounts']


okta_user_list_all_roles_policy_document = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "iam:ListRoles",
        "Resource": "*"
    }
}

okta_user_list_all_roles_policy_document = json.dumps(okta_user_list_all_roles_policy_document)

okta_user_assume_role_for_all_resources_policy_document = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "*"
    }
}

okta_user_assume_role_for_all_resources_policy_document = json.dumps(okta_user_assume_role_for_all_resources_policy_document)

for account_name, account_id in accounts.items():
    session = boto3.Session(profile_name=account_name)
    iam = session.client('iam')

    print "\n{0}\n".format(account_name)

    assume_role_for_identity_provider_access = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRoleWithSAML",
                "Principal": {
                    "Federated": "arn:aws:iam::{0}:saml-provider/Okta".format(account_id)
                },
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml"}}}]}

    assume_role_for_identity_provider_access = json.dumps(assume_role_for_identity_provider_access)
    try:
        iam.create_user(UserName='OktaSSO')
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    try:
        iam.create_group(GroupName='OktaSSO-Group')
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    try:
        okta_user_list_all_roles_policy = iam.create_policy(PolicyName='okta_user_list_all_roles_policy', PolicyDocument=okta_user_list_all_roles_policy_document)
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    try:
        okta_user_assume_role_for_all_resources_policy = iam.create_policy(PolicyName='okta_user_assume_role_for_all_resources_policy', PolicyDocument=okta_user_assume_role_for_all_resources_policy_document)
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    okta_user_list_all_roles_policy_arn = okta_user_list_all_roles_policy['Policy']['Arn']
    okta_user_assume_role_for_all_resources_policy_arn = okta_user_assume_role_for_all_resources_policy['Policy']['Arn']
    iam.attach_group_policy(GroupName='OktaSSO-Group', PolicyArn=okta_user_list_all_roles_policy_arn)
    iam.attach_group_policy(GroupName='OktaSSO-Group',PolicyArn=okta_user_assume_role_for_all_resources_policy_arn)
    iam.add_user_to_group(GroupName='OktaSSO-Group',UserName='OktaSSO')

    policy_errors = []
    print '\n' + account_name + '\n'
    # Create roles in the cross account_name per user
    list_users_paginator = iam.get_paginator('list_users')
    list_users=list_users_paginator.paginate()
    list_user_details=list_users.build_full_result()
    for user in list_user_details['Users']:
        username = user['UserName']
        role_name = '{0}-{1}'.format(username,account_name)
        all_policies_names = []
        list_policies_paginator = iam.get_paginator('list_policies')
        list_policies = list_policies_paginator.paginate()
        list_policy_details = list_policies.build_full_result()
        for policy in list_policy_details['Policies']:
            all_policies_names.append(policy['PolicyName'])

        assume_role_policy_name = username + '-' + account_name + '-policy'
        try:
            iam.create_role(RoleName=role_name,AssumeRolePolicyDocument=assume_role_for_identity_provider_access)
        except iam.exceptions.EntityAlreadyExistsException:
            pass
        except iam.exceptions.ClientError:
            policy_errors.append(assume_role_policy_name)

        # attach user's inline policies to role_name
        list_user_inline_policies_paginator = \
            iam.get_paginator('list_user_policies')
        list_user_inline_policies = \
            list_user_inline_policies_paginator.paginate(UserName=username)
        list_user_inline_policies_details = \
            list_user_inline_policies.build_full_result()
        for inline_policy in list_user_inline_policies_details['PolicyNames']:
            if inline_policy in all_policies_names:
                inline_policy_arn = 'arn:aws:iam::{0}:policy/{1}'.format(account_id, inline_policy)
                try:
                    iam.attach_role_policy(PolicyArn=inline_policy_arn,RoleName=role_name)
                except iam.exceptions.NoSuchEntityException:
                    inline_policy_arn = 'arn:aws:iam::aws:policy/{1}'.format(account_id, inline_policy)
                    iam.attach_role_policy(PolicyArn=inline_policy_arn,RoleName=role_name)
                except iam.exceptions.ClientError:
                    policy_errors.append(assume_role_policy_name)
            else:
                user_inline_policy_details = iam.get_user_policy(UserName=username,PolicyName=inline_policy)
                user_inline_policy_document = json.dumps(user_inline_policy_details['PolicyDocument'])
                print user_inline_policy_document
                try:
                    new_aws_managed_policy = iam.create_policy(PolicyName=inline_policy, PolicyDocument=user_inline_policy_document)
                except iam.exceptions.EntityAlreadyExistsException:
                    pass
                except iam.exceptions.MalformedPolicyDocumentException:
                    user_inline_policy_details['PolicyDocument']["Version"] = "2012-10-17"
                    user_inline_policy_document = json.dumps(user_inline_policy_details['PolicyDocument'])
                    new_aws_managed_policy = iam.create_policy(PolicyName=inline_policy, PolicyDocument=user_inline_policy_document)
                new_aws_managed_policy_arn =  new_aws_managed_policy['Policy']['Arn']
                print new_aws_managed_policy_arn
                try:
                    iam.attach_role_policy(PolicyArn=new_aws_managed_policy_arn,RoleName=role_name)
                except iam.exceptions.ClientError:
                    policy_errors.append(assume_role_policy_name)
                all_policies_names.append(inline_policy)

        # attach user's aws managed policies to role_name
        list_user_attached_policies_paginator = iam.get_paginator('list_attached_user_policies')
        list_user_attached_policies = \
            list_user_attached_policies_paginator.paginate(UserName=username)
        list_user_attached_policies_details = list_user_attached_policies.build_full_result()
        for attached_policy in list_user_attached_policies_details['AttachedPolicies']:
            user_attached_policy_arn = attached_policy['PolicyArn']
            print user_attached_policy_arn
            try:
                iam.attach_role_policy(PolicyArn=user_attached_policy_arn,RoleName=role_name)
            except iam.exceptions.ClientError:
                policy_errors.append(assume_role_policy_name)

        list_user_groups_paginator = iam.get_paginator('list_groups_for_user')
        list_user_groups = list_user_groups_paginator.paginate(
            UserName=username)
        list_user_groups_details = list_user_groups.build_full_result()
        for group in list_user_groups_details['Groups']:
            group_name = group['GroupName']
            # attach group's inline policies to role_name
            list_group_inline_policies_paginator = iam.get_paginator('list_group_policies')
            list_group_inline_policies = list_group_inline_policies_paginator.paginate(GroupName=group_name)
            list_group_inline_policies_details = list_group_inline_policies.build_full_result()
            for inline_policy in list_group_inline_policies_details['PolicyNames']:
                if inline_policy in all_policies_names:
                    inline_policy_arn = 'arn:aws:iam::{0}:policy/{1}'.format(account_id, inline_policy)
                    try:
                        iam.attach_role_policy(PolicyArn=inline_policy_arn,RoleName=role_name)
                    except iam.exceptions.NoSuchEntityException:
                        inline_policy_arn = 'arn:aws:iam::aws:policy/{1}'.format(account_id, inline_policy)
                        iam.attach_role_policy(PolicyArn=inline_policy_arn,RoleName=role_name)
                    except iam.exceptions.ClientError:
                        policy_errors.append(assume_role_policy_name)

                else:
                    group_inline_policy_details = iam.get_group_policy(GroupName=group_name,PolicyName=inline_policy)
                    print group_inline_policy_details['PolicyDocument']
                    group_inline_policy_document = json.dumps(group_inline_policy_details['PolicyDocument'])
                    try:
                        new_aws_managed_policy = iam.create_policy(PolicyName=inline_policy, PolicyDocument=group_inline_policy_document)
                    except iam.exceptions.EntityAlreadyExistsException:
                        pass
                    except iam.exceptions.MalformedPolicyDocumentException:
                        group_inline_policy_details['PolicyDocument']["Version"] = "2012-10-17"
                        group_inline_policy_document = json.dumps(group_inline_policy_details['PolicyDocument'])
                        new_aws_managed_policy = iam.create_policy(PolicyName=inline_policy, PolicyDocument=group_inline_policy_document)

                    new_aws_managed_policy_arn =  new_aws_managed_policy['Policy']['Arn']
                    try:
                        iam.attach_role_policy(PolicyArn=new_aws_managed_policy_arn,RoleName=role_name)
                    except iam.exceptions.ClientError:
                        policy_errors.append(assume_role_policy_name)
                    all_policies_names.append(inline_policy)

            # attach group's aws managed policies to role_name
            list_group_attached_policies_paginator = iam.get_paginator('list_attached_group_policies')
            list_group_attached_policies = list_group_attached_policies_paginator.paginate(GroupName=group_name)
            list_group_attached_policies_details = list_group_attached_policies.build_full_result()
            for attached_policy in list_group_attached_policies_details['AttachedPolicies']:
                group_attached_policy_arn = attached_policy['PolicyArn']
                print group_attached_policy_arn
                try:
                    iam.attach_role_policy(PolicyArn=group_attached_policy_arn,RoleName=role_name)
                except iam.exceptions.ClientError:
                    policy_errors.append(assume_role_policy_name)
