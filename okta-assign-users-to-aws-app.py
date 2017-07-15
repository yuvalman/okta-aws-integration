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


def config_var(config_file_path):
    with open(config_file_path) as config:
        conf_var = yaml.load(config.read())
        return conf_var


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

conf_vars = config_var(
    '/home/yuvalm-pcu/Documents/scripts/okta-aws-config.yaml')
accounts = conf_vars['accounts']
user_email_domain = conf_vars['user_email_domain']
# okta API
okta_api_access_token = conf_vars['okta_api_access_token']
okta_api_org = conf_vars['okta_api_org']
headers = {'Accept': 'application/json', 'Content-Type': 'application/json',
           "Authorization": 'SSWS {0}'.format(okta_api_access_token)}

xml_headers = {'Accept': 'application/xml', 'Content-Type': 'application/json',
               "Authorization": 'SSWS {0}'.format(okta_api_access_token)}

list_okta_apps =\
    "https://{0}.okta.com/api/v1/apps?limit=200".format(okta_api_org)
request_for_get_okta_apps = requests.get(list_okta_apps, headers=headers)

get_okta_apps = request_for_get_okta_apps.json()
list_okta_users =\
    "https://{0}.okta.com/api/v1/users?limit=200".format(okta_api_org)
request_for_get_okta_users = requests.get(list_okta_users, headers=headers)
get_okta_users = request_for_get_okta_users.json()

xml_headers = {'Accept': 'application/xml',
               'Content-Type': 'application/json',
               "Authorization": 'SSWS {0}'.format(okta_api_access_token)}
logger.info('Start assigning users to aws app with the appropriate SAML role')
for account_name, account_id in accounts.items():
    session = boto3.Session(profile_name=account_name)
    iam = session.client('iam')
    list_users_paginator = iam.get_paginator('list_users')
    list_users = list_users_paginator.paginate()
    list_user_details = list_users.build_full_result()
    for user in list_user_details['Users']:
        aws_username = user['UserName']
        role_name = '{0}-{1}'.format(aws_username, account_name)
        for app in get_okta_apps:
            if app['name'] == 'amazon_aws':
                for okta_user in get_okta_users:
                    okta_user_name =\
                        '{0}@{1}'.format(aws_username.lower(),user_email_domain)
                    okta_user_login = okta_user['profile']['login'].lower()
                    if okta_user_name == okta_user_login:
                        okta_user_id = okta_user['id']
                        data = {"id": okta_user_id, "scope": "USER",
                                "credentials": {"userName": aws_username},
                                'profile': {"samlRoles": [role_name]}}
                        get_users_in_app =\
                            "https://{1}.okta.com/api/v1/" \
                            "apps/{0}/users".format(app['id'], okta_api_org)
                        request_for_get_users_in_app =\
                            requests.get(get_users_in_app, headers=headers)
                        assign_user =\
                            requests.post(
                                get_users_in_app,
                                data=json.dumps(data), headers=headers)
logger.info('Finished assigning users to aws app with the appropriate SAML role')