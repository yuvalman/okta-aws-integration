# okta-aws-integration

This tool is used to easily integrate AWS with Okta.

This tool will help for organization 
that have restricted permissions per user
or for organization that is manage his permissions by groups and not by roles.


The tool take all the user's policies that the user has from groups and his 
inner policies and create a SAML role that can be assigned to the user in Okta

Before getting started you will have to set up your okta-aws confige file.

So, add these details to your config file in yaml format.


create "Amazon Web Services" in your Okta admin console for every account that you hare manage.

run okta-aws-create-role-per-user-per-account.py script.

run okta-assign-users-to-aws-app.py(You can change the format to what you are having already aws).


