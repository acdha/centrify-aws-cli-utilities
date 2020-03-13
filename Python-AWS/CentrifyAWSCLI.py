#!/usr/bin/env python
#
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

import argparse
import logging
import os
import re
import sys
import traceback
from getpass import getuser

from aws import assumerolesaml
from centrify import cenapp, cenauth, uprest
from config import environment, readconfig


def get_environment(args):
    tenant = args.tenant
    if ("centrify.com" not in tenant):
        tenant = tenant + ".centrify.com"
    name = tenant.split(".")[0]
    tenant = "https://" + tenant
    env = environment.Environment(name, tenant, args.cert, args.debug,
                                  args.username)
    return env

def login_instance(proxy, environment):
    if not environment.username:
        user = input("Please enter your username : ")
    else:
        user = environment.username

    version = "1.0"
    #session = cenauth.centrify_interactive_login(environment.get_endpoint(), user, version, environment.get_certpath(), proxy)
    session = cenauth.centrify_interactive_login(user, version, proxy, environment)
    return session, user

def set_logging():
    logging.basicConfig(handlers=[logging.FileHandler("centrify-python-aws.log", "w", "utf-8")], level=logging.INFO, format="%(asctime)s %(filename)s %(funcName)s %(lineno)d %(message)s")
    logging.info("Starting App..")
    print("Logfile - centrify-python-aws.log")


def select_app(awsapps):
    print("Select the aws app to login. Type 'quit' or 'q' to exit")
    count = 1
    for app in awsapps:
        print(str(count) + " : " + app["DisplayName"] + " | " + app["AppKey"])
        count = count+1
    if (len(awsapps) == 1):
        return "1"
    return input("Enter Number : ")


def client_main():
    parser = argparse.ArgumentParser(description="Enter Centrify Credentials and choose AWS Role to create AWS Profile. Use this AWS Profile to run AWS commands.")
    parser.add_argument("--username", "-u",
                        help="Use a username other than %(default)s",
                        default=os.environ.get("CENTRIFY_USERNAME", getuser()))
    parser.add_argument("--tenant", "-t", help="Enter tenant url or name e.g. cloud.centrify.com or cloud", default="cloud")
    parser.add_argument("--region", "-r", help="Enter AWS region. Default is %(default)s", default=os.environ.get("AWS_DEFAULT_REGION", "us-west-2"))
    parser.add_argument("--cert", "-c", help="Custom certificate file name. Default is the standard browser root.", default=None)
    parser.add_argument("--debug", "-d", help="This will make debug on", action="store_true")
    parser.add_argument("--use-app-name-for-profile", help="Use the application name for the profile's name",
                        action="store_true",
                        default=os.environ.get("CENTRIFY_USE_APP_NAME_FOR_PROFILE", "") == "true")
    args = parser.parse_args()

    set_logging()

    # FIXME: assume no if the file doesn't exist
    try:
        proxy_obj = readconfig.read_config()
    except Exception:
        raise RuntimeError("proxy.properties file not found. Please make sure the files are at home dir of the script.")
    proxy = {}
    if proxy_obj.is_proxy() == "yes":
        proxy={ "http":proxy_obj.get_http(), "https":proxy_obj.get_https(), "username":proxy_obj.get_user(), "password":proxy_obj.get_password() }
    environment = get_environment(args)
    session, user = login_instance(proxy, environment)

    region = args.region

    response = uprest.get_applications(user, session, environment, proxy)
    result = response["Result"]
    apps = result["Apps"]

    awsapps = []
    for app in apps:
        if app.get("WebAppType") == "UsernamePassword":
            continue

        template_name = app.get("TemplateName", "")

        if "AWS" in template_name or "Amazon" in template_name:
            awsapps.append(app)

    awsapps.sort(key=lambda i: i["DisplayName"])

    logging.info("AWSapps : %s", awsapps)

    if not awsapps:
        print("No AWS Applications to select for the user " + user, file=sys.stderr)
        return

    pattern = re.compile("[^0-9.]")
    count = 1
    profilecount = [0] * len(awsapps)
    while(True):
        number = select_app(awsapps)
        if (number == ""):
            continue
        if (re.match(pattern, number)):
            print("Exiting..")
            break
        if (int(number) - 1 >= len(awsapps)):
            continue

        appkey = awsapps[int(number)-1]["AppKey"]
        display_name = awsapps[int(number)-1]["DisplayName"]
        print("Calling app with key : " + appkey)
        encoded_saml = cenapp.call_app(session, appkey, "1.0", environment, proxy)
        while(True):
            _quit, awsinputs = cenapp.choose_role(encoded_saml, appkey)
            if (_quit == "q"):
                break;
            count = profilecount [int(number)-1]
            assumed = assumerolesaml.assume_role_with_saml(awsinputs.role, awsinputs.provider, awsinputs.saml, count, display_name, region,
                                                           use_app_name_for_profile=args.use_app_name_for_profile)
            if (assumed):
                profilecount [int(number)-1] = count + 1
            if (_quit == "one_role_quit"):
                break

        if (len(awsapps) == 1):
            break

    logging.info("Done")
    logging.shutdown()

try:
    client_main()
except SystemExit as se:
    if se.code != 0:
        print("Program Exited due to error or wrong input...", file=sys.stderr)
        logging.exception("Program Exited due to error or wrong input..")
except:
    logging.exception("Unhandled Exception")
    # FIXME: configure logging to display to the console as well
    print("Program Exited due to unhandled exception...", file=sys.stderr)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_exception(exc_type, exc_value, exc_traceback)
finally:
    logging.shutdown()
