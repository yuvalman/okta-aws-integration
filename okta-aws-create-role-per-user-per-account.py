########
# Copyright (c) 2017 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.


import boto3
import json
import requests
import yaml
import logging


def _config_var(config_file_path):
    with open(config_file_path) as config:
        conf_vars = yaml.load(config.read())
        return conf_vars

log_format =\
    '[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s'
logging.basicConfig(
    format=log_format, datefmt='%m-%d %H:%M:%S', level=logging.INFO)
logger = logging.getLogger(__name__)

conf_vars = _config_var(
    '/home/yuvalm-pcu/Documents/scripts/okta-aws-config.yaml')
accounts = conf_vars['accounts']

# okta API
okta_api_access_token = conf_vars['okta_api_access_token']
okta_api_org = conf_vars['okta_api_org']
headers = {'Accept': 'application/json', 'Content-Type': 'application/json',
           "Authorization": 'SSWS {0}'.format(okta_api_access_token)}

xml_headers = {'Accept': 'application/xml', 'Content-Type': 'application/json',
               "Authorization": 'SSWS {0}'.format(okta_api_access_token)}

list_okta_apps = \
    "https://{0}.okta.com/api/v1/apps?limit=200".format(okta_api_org)
request_for_get_okta_apps = requests.get(list_okta_apps, headers=headers)

get_okta_apps = request_for_get_okta_apps.json()

okta_user_list_all_roles_policy_document = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "iam:ListRoles",
        "Resource": "*"
    }
}

okta_user_list_all_roles_policy_document = \
    json.dumps(okta_user_list_all_roles_policy_document)

okta_user_assume_role_for_all_resources_policy_document = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "*"
    }
}

okta_user_assume_role_for_all_resources_policy_document = \
    json.dumps(okta_user_assume_role_for_all_resources_policy_document)

for account_name, account_id in accounts.items():
    session = boto3.Session(profile_name=account_name)
    iam = session.client('iam')
    logger.info('Working on {0} aws account'.format(account_name))
    for app in get_okta_apps:
        if account_name == app['label']:
            identity_provider_name = 'Okta'
            try:
                logger.info(
                    'Creating the identity porvider: {1} in'
                    ' {0} aws account'.format(
                        account_name, identity_provider_name))
                okta_app_metadata = \
                    'https://{2}.okta.com/api/v1/apps/{0}/sso/saml/'\
                    'metadata?kid={1}'.format(
                        app['id'],
                        app['credentials']['signing']['kid'],
                        okta_api_org)
                request_for_get_okta_app_metadata = requests.get(
                    okta_app_metadata, headers=xml_headers)
                get_okta_app_metadata =\
                    request_for_get_okta_app_metadata.content
                response = iam.create_saml_provider(
                    SAMLMetadataDocument=get_okta_app_metadata,
                    Name=identity_provider_name
                )
            except iam.exceptions.EntityAlreadyExistsException:
                logger.warning('The Identity provider {0} is already exist, '
                               'you can change the Identity provider name for '
                               'creating a new Identity provider'.format(
                                identity_provider_name))
    okta_user_with_permissions = 'OktaSSO'
    okta_group_with_permissions = 'OktaSSO-Group'
    logger.info(
        'Creating user with permission for listing and assuming all '
        'roles in {0} aws account'.format(account_name))
    try:
        iam.create_user(UserName=okta_user_with_permissions)
    except iam.exceptions.EntityAlreadyExistsException:
        logger.warning(
            'The user {0} already exist, '
            'you can change the user name for creating a new user'.format(
                okta_user_with_permissions))
    try:
        iam.create_group(GroupName=okta_group_with_permissions)
    except iam.exceptions.EntityAlreadyExistsException:
        logger.warning('The group {0} already exist, '
                       'you can change the group name for '
                       'creating a new group'.format(
                        okta_group_with_permissions))

    okta_user_list_all_roles_policy_name = 'okta_user_list_all_roles_policy'
    try:
        okta_user_list_all_roles_policy = \
            iam.create_policy(
                PolicyName=okta_user_list_all_roles_policy_name,
                PolicyDocument=okta_user_list_all_roles_policy_document)
    except iam.exceptions.EntityAlreadyExistsException:
        logger.warning(
            'The policy {0} already exist, '
            'you can change the policy'
            ' name for creating a new policy'.format(
                okta_user_list_all_roles_policy_name))

    okta_user_assume_role_for_all_resources_policy_name =\
        'okta_user_assume_role_for_all_resources_policy'
    try:
        okta_user_assume_role_for_all_resources_policy =\
            iam.create_policy(
                PolicyName=okta_user_assume_role_for_all_resources_policy_name,
                PolicyDocument=okta_user_assume_role_for_all_resources_policy_document)
    except iam.exceptions.EntityAlreadyExistsException:
        logger.warning(
            'The policy {0} already exist, '
            'you can change the policy name'
            ' for creating a new policy'.format(
                okta_user_assume_role_for_all_resources_policy_name))
    try:
        okta_user_list_all_roles_policy_arn =\
        okta_user_list_all_roles_policy['Policy']['Arn']
    except NameError:
        okta_user_list_all_roles_policy_arn =\
            'arn:aws:iam::{0}:policy/' \
            'okta_user_list_all_roles_policy'.format(account_id)
    try:
        okta_user_assume_role_for_all_resources_policy_arn =\
        okta_user_assume_role_for_all_resources_policy['Policy']['Arn']
    except NameError:
        okta_user_assume_role_for_all_resources_policy_arn =\
            'arn:aws:iam::{0}:policy/' \
            'okta_user_assume_role_for_all_resources_policy'.format(account_id)
    iam.attach_group_policy(GroupName=okta_group_with_permissions,
                            PolicyArn=okta_user_list_all_roles_policy_arn)
    iam.attach_group_policy(GroupName=okta_group_with_permissions,
                            PolicyArn=okta_user_assume_role_for_all_resources_policy_arn)
    iam.add_user_to_group(GroupName=okta_group_with_permissions,
                          UserName=okta_user_with_permissions)

    assume_role_for_identity_provider_access = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRoleWithSAML",
                "Principal": {
                    "Federated": "arn:aws:iam::{0}:saml-provider/Okta".format(
                        account_id)
                },
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml"}}}]}

    assume_role_for_identity_provider_access =\
        json.dumps(assume_role_for_identity_provider_access)
    list_users_paginator = iam.get_paginator('list_users')
    list_users = list_users_paginator.paginate()
    list_user_details = list_users.build_full_result()
    for user in list_user_details['Users']:
        username = user['UserName']
        role_name = '{0}-{1}'.format(username, account_name)
        logger.info('Creating the role {2} in the {0} for the user {1}'.format(
            account_name, username, role_name))
        all_policies_names = []
        list_policies_paginator = iam.get_paginator('list_policies')
        list_policies = list_policies_paginator.paginate()
        list_policy_details = list_policies.build_full_result()
        for policy in list_policy_details['Policies']:
            all_policies_names.append(policy['PolicyName'])

        assume_role_policy_name = '{0}-{1}-policy'.format(username,
                                                          account_name)
        try:
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=assume_role_for_identity_provider_access)
        except iam.exceptions.EntityAlreadyExistsException:
            logger.warning(
                'The role {0} already exist, '
                'you can change the role name for creating a new role'.format(
                    role_name))
        except iam.exceptions.ClientError:
            logger.error(
                'The role {0} is too long, '
                'you can change the role name to a shorter one.'.format(
                    role_name))
        # attach user's inline policies to role_name
        list_user_inline_policies_paginator =\
            iam.get_paginator('list_user_policies')
        list_user_inline_policies =\
            list_user_inline_policies_paginator.paginate(UserName=username)
        list_user_inline_policies_details =\
            list_user_inline_policies.build_full_result()
        for inline_policy in list_user_inline_policies_details['PolicyNames']:
            if inline_policy in all_policies_names:
                inline_policy_arn = 'arn:aws:iam::{0}:policy/{1}'.format(
                    account_id, inline_policy)
                try:
                    iam.attach_role_policy(
                        PolicyArn=inline_policy_arn, RoleName=role_name)
                except iam.exceptions.NoSuchEntityException:
                    inline_policy_arn = 'arn:aws:iam::aws:policy/{1}'.format(
                        account_id, inline_policy)
                    iam.attach_role_policy(
                        PolicyArn=inline_policy_arn, RoleName=role_name)
                except iam.exceptions.ClientError:
                    logger.error(
                        'The role {0} got to his maximum policies attached, '
                        'contact AWS support for '
                        'increasing the limit of PoliciesPerRole').format(
                        role_name)
            else:
                user_inline_policy_details =\
                    iam.get_user_policy(
                        UserName=username, PolicyName=inline_policy)
                user_inline_policy_document =\
                    json.dumps(user_inline_policy_details['PolicyDocument'])
                try:
                    new_aws_managed_policy =\
                        iam.create_policy(
                            PolicyName=inline_policy,
                            PolicyDocument=user_inline_policy_document)
                except iam.exceptions.EntityAlreadyExistsException:
                    logger.warning(
                        'The policy {0} already exist, '
                        'you can change the policy name for '
                        'creating a new policy'.format(inline_policy))
                except iam.exceptions.MalformedPolicyDocumentException:
                    user_inline_policy_details['PolicyDocument']["Version"] =\
                        "2012-10-17"
                    user_inline_policy_document =\
                        json.dumps(
                            user_inline_policy_details['PolicyDocument'])
                    new_aws_managed_policy =\
                        iam.create_policy(
                            PolicyName=inline_policy,
                            PolicyDocument=user_inline_policy_document)
                new_aws_managed_policy_arn =\
                    new_aws_managed_policy['Policy']['Arn']
                try:
                    iam.attach_role_policy(
                        PolicyArn=new_aws_managed_policy_arn,
                        RoleName=role_name)
                except iam.exceptions.ClientError:
                    logger.error(
                        'The role {0} got to his maximum policies attached, '
                        'contact AWS support for increasing the limit quotas '
                        'for PoliciesPerRole in the account {1}'.format(
                            role_name, account_name))
                all_policies_names.append(inline_policy)

        # attach user's aws managed policies to role_name
        list_user_attached_policies_paginator =\
            iam.get_paginator('list_attached_user_policies')
        list_user_attached_policies =\
            list_user_attached_policies_paginator.paginate(UserName=username)
        list_user_attached_policies_details =\
            list_user_attached_policies.build_full_result()
        for attached_policy in\
                list_user_attached_policies_details['AttachedPolicies']:
            user_attached_policy_arn = attached_policy['PolicyArn']
            try:
                iam.attach_role_policy(
                    PolicyArn=user_attached_policy_arn, RoleName=role_name)
            except iam.exceptions.ClientError:
                logger.error(
                    'The role {0} got to his maximum policies attached, '
                    'contact AWS support for increasing the limit quotas for '
                    'PoliciesPerRole in the account {1}'.format(
                        role_name, account_name))
        list_user_groups_paginator = iam.get_paginator('list_groups_for_user')
        list_user_groups = list_user_groups_paginator.paginate(
            UserName=username)
        list_user_groups_details = list_user_groups.build_full_result()
        for group in list_user_groups_details['Groups']:
            group_name = group['GroupName']
            # attach group's inline policies to role_name
            list_group_inline_policies_paginator =\
                iam.get_paginator('list_group_policies')
            list_group_inline_policies =\
                list_group_inline_policies_paginator.paginate(
                    GroupName=group_name)
            list_group_inline_policies_details =\
                list_group_inline_policies.build_full_result()
            for inline_policy in\
                    list_group_inline_policies_details['PolicyNames']:
                if inline_policy in all_policies_names:
                    inline_policy_arn =\
                        'arn:aws:iam::{0}:policy/{1}'.format(
                            account_id, inline_policy)
                    try:
                        iam.attach_role_policy(
                            PolicyArn=inline_policy_arn, RoleName=role_name)
                    except iam.exceptions.NoSuchEntityException:
                        inline_policy_arn =\
                            'arn:aws:iam::aws:policy/{0}'.format(inline_policy)
                        iam.attach_role_policy(
                            PolicyArn=inline_policy_arn, RoleName=role_name)
                    except iam.exceptions.ClientError:
                        logger.error(
                            'The role {0} got to his maximum '
                            'policies attached, contact AWS support for '
                            'increasing the limit quotas for '
                            'PoliciesPerRole in the account {1}'.format(
                                role_name, account_name))
                else:
                    group_inline_policy_details =\
                        iam.get_group_policy(
                            GroupName=group_name, PolicyName=inline_policy)
                    group_inline_policy_document =\
                        json.dumps(
                            group_inline_policy_details['PolicyDocument'])
                    try:
                        new_aws_managed_policy =\
                            iam.create_policy(
                                PolicyName=inline_policy,
                                PolicyDocument=group_inline_policy_document)
                    except iam.exceptions.EntityAlreadyExistsException:
                        logger.warning(
                            'The policy {0} already exist, '
                            'you can change the policy name for '
                            'creating a new policy'.format(inline_policy))
                    except iam.exceptions.MalformedPolicyDocumentException:
                        group_inline_policy_details[
                            'PolicyDocument']["Version"] = "2012-10-17"
                        group_inline_policy_document =\
                            json.dumps(
                                group_inline_policy_details['PolicyDocument'])
                        new_aws_managed_policy =\
                            iam.create_policy(
                                PolicyName=inline_policy,
                                PolicyDocument=group_inline_policy_document)
                    new_aws_managed_policy_arn =\
                        new_aws_managed_policy['Policy']['Arn']
                    try:
                        iam.attach_role_policy(
                            PolicyArn=new_aws_managed_policy_arn,
                            RoleName=role_name)
                    except iam.exceptions.ClientError:
                        logger.error(
                            'The role {0} got to his maximum '
                            'policies attached, contact AWS support for '
                            'increasing the limit quotas for '
                            'PoliciesPerRole in the account {1}'.format(
                                role_name, account_name))
                    all_policies_names.append(inline_policy)

            # attach group's aws managed policies to role_name
            list_group_attached_policies_paginator =\
                iam.get_paginator('list_attached_group_policies')
            list_group_attached_policies =\
                list_group_attached_policies_paginator.paginate(
                    GroupName=group_name)
            list_group_attached_policies_details =\
                list_group_attached_policies.build_full_result()
            for attached_policy in\
                    list_group_attached_policies_details['AttachedPolicies']:
                group_attached_policy_arn = attached_policy['PolicyArn']
                try:
                    iam.attach_role_policy(
                        PolicyArn=group_attached_policy_arn,
                        RoleName=role_name)
                except iam.exceptions.ClientError:
                    logger.error(
                        'The role {0} got to his maximum '
                        'policies attached, contact AWS support for '
                        'increasing the limit quotas for '
                        'PoliciesPerRole in the account {1}'.format(
                            role_name, account_name))
