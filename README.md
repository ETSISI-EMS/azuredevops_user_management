# Azuredevops User Management

Script to read user emails from a csv file and automatically add them to an azuredevops organization with specific group permissions

# Prerequisites

The next software needs to be installed in the system:

* [Python >= 3.10](https://www.python.org/downloads)
* [Pip >= 20.3.4](https://pypi.org)

# Set up

1. Install the requirements of the script running `pip install -r requirements.txt`
2. Create a *.env* file with the required configuration information

## .env file format

The .env file should be located at the root of folder of this proyect and contain the next fields

```
ACCESS_TOKEN= Access Token generated from your azuredevops account to login into your account
ORGANIZATION= The name of the organization where the users will be added, the owner of the access token must have the neccesary permissions to manage this organization
GROUP_PERMISSIONS_NAME= The name of the permissions group where the users are added (the available ones can be found at https://dev.azure.com/${ORGANIZATION}/_settings/groups)
```

# Running the script

The script must be runned with the next command

```
python3 load_users.py csv_file [--vervose -v] [--error -e]
```

* **csv_file**: mandatory field with the .csv file with the emails. The file must contain at least one column named *'Email'*, the column separator must be ';' and the row one must be '\n'.
* **debug**: optional flag that runs the program with debug information
* **error**: optional flag, when present the emails that were not processed due to some error are stored in txt files



