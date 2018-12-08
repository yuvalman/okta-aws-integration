# okta-aws-integration tool

This tool is used to easily integrate AWS with Okta.

This tool will help for organization 
that have restricted permissions per user(For example: user has permission only for his own bucket),
or for organization that is manage his user's permissions by groups.


The tool take all the user's policies that the user has from his groups and his 
inner policies and create a SAML role that can be assigned to the user in Okta


## Setup

Before getting started you will have to set up your enviornment:

- Use ```https://github.com/yuvalman/okta-aws-integration.git``` to clone the repository locally.
- Install awscli by using this [instructions](http://docs.aws.amazon.com/cli/latest/userguide/installing.html)
- Edit your AWS credentials file by adding access key and secret access key of a user with full access to IAM in every AWS account for every AWS account profile.
The AWS credentials file located at ~/.aws/credentials on Linux, macOS, or Unix, or at C:\Users\USERNAME \.aws\credentials on Windows. This file can contain multiple named profiles in addition to a default profile.
For example:



```
[pm]
aws_access_key_id=foo
aws_secret_access_key=bar

[dev]
aws_access_key_id=foo2
aws_secret_access_key=bar2

[ops]
aws_access_key_id=foo3
aws_secret_access_key=bar3
```


Edit the okta-aws-confige.yaml file:

- Add the profile names of the accounts that you have and their ID under the accounts statement
- Add your Okta API access token(You can get it by using these [instructions](https://developer.okta.com/docs/api/getting_started/getting_a_token.html)
- Add you Okta Org(You can find it in your Okta sign-in page - https://<Okta Org>.okta.com)
```
accounts:
  pm : <pm account id>
  dev : <dev account id>
  ops : <ops account id>
  
okta_api_access_token: <Your Okta org api access token>

okta_api_org: <Your Okta Org>

user_email_domain : <Your users email domain>
```
Create "Amazon Web Services" app in your Okta admin console for every account that you manage. You can use this [guide](https://support.okta.com/help/servlet/fileField?retURL=%2Fhelp%2Farticles%2FKnowledge_Article%2FAmazon-Web-Services-and-Okta-Integration-Guide&entityId=ka0F0000000MeyyIAC&field=File_Attachment__Body__s)(Page 16-20) for creating the aws app.

## Run

- Run okta-aws-create-role-per-user-per-account.py script.

- Click on the "Refresh Application Data" button in the right side of your application home page in your Okta Admin console for syncing the aws roles with Okta.

- Run okta-assign-users-to-aws-app.py(On line 56-57 in the code, you can change the username format for the format you are using: in our AWS accounts the username format was the email prefix, so, we modified the username that will be fit to the okta username).


