# Copyright 2018 Centrify Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function

import logging
import re

import boto3
from botocore.exceptions import ClientError

from .util import load_aws_credentials


def write_cred(
    cred,
    display_name,
    region,
    role,
    use_app_name_for_profile=False,
    credentials_filename=None,
):
    config, credentials_filename = load_aws_credentials(path=credentials_filename)

    print("Display Name : " + display_name)
    rolesplit = role.split("/")
    profile_name = rolesplit[1] + "_profile"

    if use_app_name_for_profile:
        section = re.sub(r"^aws-", "", display_name, flags=re.IGNORECASE)
        section = re.sub(r"[^-_\w]+", "", section)
    else:
        section = profile_name

    if not config.has_section(section):
        config.add_section(section)
    config.set(section, "output", "json")
    config.set(section, "region", region)
    config.set(section, "centrify_application_name", display_name)
    config.set(section, "centrify_role", role)
    config.set(section, "aws_access_key_id", cred["Credentials"]["AccessKeyId"])
    config.set(section, "aws_secret_access_key", cred["Credentials"]["SecretAccessKey"])
    config.set(section, "aws_session_token", cred["Credentials"]["SessionToken"])
    with open(credentials_filename, "w+") as credentials:
        config.write(credentials)
    print("\n\n")
    print("-" * 80)
    print(
        "Your profile is created. It will expire at "
        + str(cred["Credentials"]["Expiration"])
    )
    print("Use --profile " + section + " for the commands")
    print("Example - ")
    print("aws s3 ls --profile " + section)
    print("-" * 80)


def assume_role_with_saml(
    role, principle, saml, display_name, region, use_app_name_for_profile=False
):
    stsclient = boto3.client("sts")

    try:
        cred = stsclient.assume_role_with_saml(
            RoleArn=role, PrincipalArn=principle, SAMLAssertion=saml
        )
    except ClientError as e:
        logging.error("Access denied: %s", e, exc_info=True)
        return False

    write_cred(
        cred,
        display_name,
        region,
        role,
        use_app_name_for_profile=use_app_name_for_profile,
    )
    return True
