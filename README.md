# aws-cli-adfs
Login to AWS CLI using Active Directory Federation Services

## Prerequisite
python version >= 3.5

## Installing

Git clone this repo, then execute
```shell
$ cd aws-cli-adfs
$ pip install .
```
or install with
```shell
pip install -U awscli-adfs
```

## Usage

#### Display the version of this tool
```shell
$ aws-adfs version
```

#### Create a profile

```shell
$ aws-adfs profile create
```
Example:
```shell
$ aws-adfs profile create
Profile Name:  cn-prod
IDP Entry Url:  https://login.your-ad-server.com/adfs/ls/idpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices:cn-north-1
IDP Username:  duck@gogo.com
IDP Role ARN:  arn:aws-cn:iam::111111111111:role/ADFS-CNAdmin
IDP Session Duration(in seconds) [3600]: 
AWS Region: cn-north-1
Output Format [json]:
Done.
```

#### List your profiles
```shell
$ aws-adfs profile ls
```

#### Show details of your profile(s)
```shell
$ aws-adfs profile show PROFILE-NAME1 PROFILE-NAME2 ...
```

#### Update your profile(s)
```shell
$ aws-adfs profile update PROFILE-NAME1 PROFILE-NAME2 ...
```

#### Set the default profile
```shell
$ aws-adfs profile default PROFILE_NAME
```
Once the default profile is set, you don't have to specify PROFILE-NAME in 'show', 'update', 'delete', 'expire-at' subcomands and 'login' command

#### Check the default profile
```shell
$ aws-adfs profile default
```

#### Delete your profile(s)
```shell
$ aws-adfs profile delete PROFILE-NAME1 PROFILE-NAME2 ...
```

#### Login with your profile(s)
```shell
$ aws-adfs login PROFILE-NAME1 PROFILE-NAME2 ...
```

#### Check the expire time of the login profile(s)
```shell
$ aws-adfs profile expire-at PROFILE-NAME1 PROFILE-NAME2 ...
```

## Log file path
~/.aws/aws-adfs.log