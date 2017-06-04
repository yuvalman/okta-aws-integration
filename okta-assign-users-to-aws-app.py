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



# okta API
okta_api_access_token = conf_vars['okta_api_access_token']
okta_api_org = conf_vars['okta_api_org']
headers = {'Accept': 'application/json', 'Content-Type': 'application/json',
           "Authorization": 'SSWS '.format(okta_api_access_token)}


list_okta_apps = "https://{0}.okta.com/api/v1/apps?limit=200".format(okta_api_org)
request_for_get_okta_apps = requests.get(list_okta_apps, headers=headers)
get_okta_apps = request_for_get_okta_apps.json()
list_okta_users = "https://{0}.okta.com/api/v1/users?limit=200".format(okta_api_org)
request_for_get_okta_users = requests.get(list_okta_users, headers=headers)
get_okta_users = request_for_get_okta_users.json()


for account_name, account_id in accounts.items():
    session = boto3.Session(profile_name=account_name)
    iam = session.client('iam')

    # Create roles in the cross account_name per user
    list_users_paginator = iam.get_paginator('list_users')
    list_users=list_users_paginator.paginate()
    list_user_details=list_users.build_full_result()
    for user in list_user_details['Users']:
        username = user['UserName']
        role_name = '{0}-{1}'.format(username,account_name)
        for app in get_okta_apps:
            if app['name'] == 'amazon_aws':
                for okta_user in get_okta_users:
                    okta_user_name = '{0}@gigaspaces.com'.format(username.lower())
                    okta_user_login = okta_user['profile']['login'].lower()
                    if okta_user_name == okta_user_login:
                        okta_user_id = okta_user['id']
                        print app['id']
                        print app['label']
                        data = {"id": okta_user_id, "scope": "USER",
                                "credentials": {"userName": username},
                                'profile': {"samlRoles": [role_name]}}
                        print data
                        get_users_in_app = "https://{1}.okta.com/api/v1/apps/{0}/users".format(app['id'],okta_api_org)
                        request_for_get_users_in_app = requests.get(get_users_in_app,headers=headers)
                        assign_user = requests.post(get_users_in_app, data=json.dumps(data), headers=headers)
