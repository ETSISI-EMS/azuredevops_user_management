"""
Read a csv file with email addresses and add them to an azuredevops organization via the REST API.
The csv file will be passed as an argument to the script.
"""
import argparse
import base64
import logging
import os
import pandas as pd
import requests
import traceback
from dotenv import load_dotenv
from functools import partial
from time import sleep
from tqdm import tqdm


ERROR_USERS_FILE = "error_users.txt"
ERROR_PERMISSIONS_FILE = "error_permissions.txt"


# create a custom exception called itemfound
class ItemFound(Exception):
    pass


def do_request_continuation_token(uri, process_page):
    headers = make_header()

    next_token = None
    while True:
        logging.debug(f"Requesting {uri}")
        if next_token:
            response = requests.get(url=uri + f"&continuationToken={next_token}", headers=headers)
        else:
            response = requests.get(url=uri, headers=headers)

        logging.debug(f"Response: {response.status_code}:{response.reason}")

        if response.status_code != 200:
            raise RuntimeError(f"Error calling {uri}: {response.status_code} {response.reason}")

        if response.status_code == 200:
            next_token = response.headers.get("x-ms-continuationtoken", None)
            process_page(response.json())
            logging.debug(f"Next token: {next_token}")

        if next_token == None:
            break


def make_header():
    ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
    authorization = str(base64.b64encode(bytes(':'+ACCESS_TOKEN, 'ascii')), 'ascii')
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Basic ' + authorization
    }
    return headers


def save_error_users(users, file):
    with open(file, 'w') as f:
        for user in users:
            f.write(user + '\n')


def add_user(email):
    logging.debug(f"Adding user {email}")

    ORGANIZATION = os.getenv('ORGANIZATION')
    uri = f"https://vsaex.dev.azure.com/{ORGANIZATION}/_apis/userentitlements?api-version=7.1-preview.3"

    body = {
        'accessLevel': {"accountLicenseType": "stakeholder"},
        "user": {
            "principalName": email,
            "subjectKind": "user"
        }
    }

    response = requests.post(url=uri, headers=make_header(), json=body)
    logging.debug(f"Response: {response.status_code}:{response.reason}")
    if response.status_code != 200:
        raise RuntimeError(f"Error calling {uri}: {response.status_code} {response.reason}")


def add_perimisions(user, group):
    logging.debug(f"Adding user {user} to {group}")

    ORGANIZATION = os.getenv('ORGANIZATION')
    uri = f"https://vssps.dev.azure.com/{ORGANIZATION}/_apis/graph/memberships/{user}/{group}?api-version=7.1-preview.1"
    response = requests.put(url=uri, headers=make_header())
    
    logging.debug(f"Response: {response.status_code}:{response.reason}")
    if response.status_code != 200 and response.status_code != 201:
        raise RuntimeError(f"Error calling {uri}: {response.status_code} {response.reason}")


def get_users_descriptors(emails: set):
    user_descriptors = {}

    def process_response(response, users_dict: dict):
        page_descriptors = {}
        for user in response["value"]:
            if ("origin" in user and user["origin"] == "aad") and ("mailAddress" in user and user["mailAddress"] in emails):
                page_descriptors[user["mailAddress"]] = user["descriptor"]

        users_dict.update(page_descriptors)
    
    ORGANIZATION = os.getenv('ORGANIZATION')
    callback = partial(process_response, users_dict=user_descriptors)
    uri = f"https://vssps.dev.azure.com/{ORGANIZATION}/_apis/graph/users?api-version=7.1-preview.1"
    do_request_continuation_token(uri, callback)

    return user_descriptors


def get_group_descriptor():
    GROUP_NAME = os.getenv('GROUP_PERMISSIONS_NAME')
    group_descriptor = {"descriptor": None}

    def process_response(response, group_descriptor):
        for group in response["value"]:
            if "displayName" in group and group["displayName"] == GROUP_NAME:
                group_descriptor["descriptor"] = group["descriptor"]
                raise ItemFound

    ORGANIZATION = os.getenv('ORGANIZATION')
    uri = f"https://vssps.dev.azure.com/{ORGANIZATION}/_apis/graph/groups?api-version=7.1-preview.1"
    callback = partial(process_response, group_descriptor=group_descriptor)

    try:
        do_request_continuation_token(uri, callback)
    except ItemFound:
        pass

    return group_descriptor["descriptor"]


def process_users_file(df: pd.DataFrame, error=False):
    failed_users = []
    for _, row in tqdm(df.iterrows(), total=len(df)):
        try:
            add_user(row['Email'])
            logging.debug(f"Added {row['Email']}")
            sleep(0.1)
        except RuntimeError as e:
            logging.error(e)
            failed_users.append(row['Email'])

    if error and len(failed_users) > 0:
        save_error_users(failed_users, ERROR_USERS_FILE)


def process_users_permissions(user_descriptors, group_descriptor, error=False):
    GROUP_NAME = os.getenv('GROUP_PERMISSIONS_NAME')

    failed_permissions = []
    for email, descriptor in tqdm(user_descriptors.items()):
        try:
            add_perimisions(descriptor, group_descriptor)
            logging.debug(f"Added {email} to {GROUP_NAME}")
            sleep(0.1)
        except RuntimeError as e:
            logging.error(e)
            failed_permissions.append(email)

    if error and len(failed_permissions) > 0:
        save_error_users(failed_permissions, ERROR_PERMISSIONS_FILE)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file", help="The csv file with the email addresses")
    parser.add_argument("-v", "--verbose", help="Enable debug mode", action="store_true")
    parser.add_argument("-e", "--error", help="save users that give an error into a file", action="store_true")

    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    df = pd.read_csv(args.csv_file, index_col=False)
    logging.info(f"Read {len(df)} rows from {args.csv_file}")

    logging.debug("Getting group descriptor")
    group_descriptor = get_group_descriptor()

    if group_descriptor["descriptor"] == None:
        GROUP_NAME = os.getenv('GROUP_PERMISSIONS_NAME')
        raise RuntimeError(f"Permissions group '{GROUP_NAME}' not found")

    logging.info("Adding users:")
    process_users_file(df, args.error)

    logging.debug("Getting users descriptors")
    user_descriptors = get_users_descriptors(set(df["Email"].astype(str).to_list()))

    logging.info("Setting permissions:")
    process_users_permissions(user_descriptors, group_descriptor, args.error)


if __name__ == '__main__':
    load_dotenv()
    try:
        main()
        exit(0)
    except Exception as e:
        logging.error(traceback.format_exc())
        logging.error(e)
        exit(1)