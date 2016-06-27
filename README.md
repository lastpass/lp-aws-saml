# lp-aws-saml

This repository contains the LastPass AWS SAML login tool.

If you are using LastPass Enterprise SAML with AWS, then this script eases the
process of using the AWS CLI utility.  It retrieves a SAML assertion from
LastPass and then converts it into a

## Requirements

You will need python with the Amazon boto3 module and the AWS CLI tool.
The latter may be installed with pip:
```
    # pip install boto3 awscli
```
On recent Mac platforms, you may need to pass --ignore-installed:

```
    # pip install boto3 awscli --ignore-installed
```

You will also need to have integrated AWS with LastPass SAML through the
AWS and LastPass management consoles.  See the SAML setup instructions on the
LastPass AWS configuration page for more information.

## Usage

First you will need to look up the LastPass SAML configuration ID for the AWS
instance you wish to control.  This can be obtained from the generated
Launch URL: if the launch URL is ```https://lastpass.com/saml/launch/cfg/25```
then the configuration ID is ```25```.

Then launch the tool to login to lastpass.  You will be prompted for
password and optionally the AWS role to assume:

```
$ ./lp-aws-saml.py user@example.com 25
Password:
A new AWS CLI profile 'user@example.com' has been added.
You may now invoke the aws CLI tool as follows:

    aws --profile user@example.com [...]

This token expires in one hour.
```

Once completed, the ```aws``` tool may be used to execute commands as that
user by specifying the appropriate profile.

