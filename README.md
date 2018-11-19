# aws-cli-adfs
Login to AWS CLI using Active Directory Federation Services


## Installing

Git clone this repo, then execute
```shell
cd aws-cli-adfs
pip install .
```

## Usage

### Display the version of this tool
```shell
aws-adfs version
```

#### Create a profile

```shell
aws-adfs profile create
```

#### List your profiles
```shell
aws-adfs profile ls
```

#### Show details of your profile(s)
```shell
aws-adfs profile show PROFILE-NAME1 PROFILE-NAME2 ...
```

#### Update your profile(s)
```shell
aws-adfs profile update PROFILE-NAME1 PROFILE-NAME2 ...
```

#### Set the default profile
```shell
aws-adfs profile default PROFILE_NAME
```
Once the default profile is set, you don't have to specify PROFILE-NAME in 'show', 'update', 'delete' subcomands and 'login' command

#### Check the default profile
```shell
aws-adfs profile default
```

#### Delete your profile(s)
```shell
aws-adfs profile delete PROFILE-NAME1 PROFILE-NAME2 ...
```

#### Login with your profile(s)
```shell
aws-adfs login PROFILE-NAME1 PROFILE-NAME2 ...
```

#### Check the expire time of the login profile(s)
```shell
aws-adfs profile expire-at PROFILE-NAME1 PROFILE-NAME2 ...
```

## Log path
~/.aws/aws-adfs.log