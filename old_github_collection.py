"""
This script pulls Github repositories, and sets them to their state at the specified date.

Paramters (set them in the script):
github_links - The link to each GitHub repo that should be cloned
date_to_access_string - The date the repos should be set to
MAIN_BRANCH_POSSIBLE_NAMES - The possible names for the main/master branch - for most (all?) repos, leaving this as ['main', 'master'] is sufficient.

If a GitHub repo did not exist prior to the specified date, it is simply not cloned at all.

Use extract_py_files.py to get all the .py files from the GitHub repos into one overall folder.

Version: 1.0
Date: 10-28-2024
Author(s): Anthony S
Other Info: The script to gather this was run 10-28-2024
""" 

import requests
import datetime
from subprocess import check_output
from subprocess import CalledProcessError
from typing import Tuple

import clone_and_extract
from clone_and_extract import date_to_access_string

def get_repo_creation_date(repo_api_path: str) -> Tuple[datetime.datetime | None, bool]:
    repo_json_info = requests.get(repo_api_path).json()
    try:
        creation_date_string = repo_json_info['created_at']
    except KeyError:
        print(f"Attempt to access {repo_api_path} failed with a KeyError.")
        return None, False
    creation_date = datetime.datetime.strptime(creation_date_string, "%Y-%m-%dT%H:%M:%SZ")
    return creation_date, True

def main_repo_link_to_api_request_link(main_repo_link: str) -> str:
    return main_repo_link.replace("github.com", "api.github.com/repos", 1)

def run_command_with_confirm(command_to_run: str, cwd: str | None = None) -> str:
    choice = input(f"Would you like to run '{command_to_run}'? Enter 'y' to run, 'n' to not "
    "run but not exit the script, and anything else to exit without running it: ").lower()
    if choice == 'y':
        output = str(check_output(command_to_run, shell=True, cwd=cwd), encoding='utf-8')
        return output.replace("\n", '')
    elif choice == 'n':
        return ''
    exit("Exiting script.")


MAIN_BRANCH_POSSIBLE_NAMES = ['main', 'master']

link_time_addition = f"/tree/HEAD@{'{' + date_to_access_string + '}'}" 
date_to_access_datetime = datetime.datetime.strptime(date_to_access_string, '%Y-%m-%d')

def clone_repos():
    for link in clone_and_extract.github_repos_to_clone:
        if link in clone_and_extract.github_repos_already_cloned:
            continue
        if link[-1] == "/":
            link = link[0:-1]
        creation_date, success = get_repo_creation_date(main_repo_link_to_api_request_link(link))
        if not success:
            continue
        assert creation_date is not None
        if creation_date > date_to_access_datetime:
            continue

        link_at_date_to_access = link + link_time_addition
        print(link_at_date_to_access)

        clone_repo_command = f'git clone {link}'
        cwd = link.split("/")[-1]

        print(run_command_with_confirm(clone_repo_command))

        rev_list_time_arg = run_command_with_confirm(f"git rev-parse --until={date_to_access_string}", cwd=cwd)

        commit_to_move_to = None
        for name in MAIN_BRANCH_POSSIBLE_NAMES:
            try:
                commit_to_move_to = run_command_with_confirm(f"git rev-list -1 {rev_list_time_arg} {name}", cwd=cwd)
                break
            except CalledProcessError:
                print(f"Command failed with {name} as the main/master branch. This is OK if it's just named the other one")
        
        reset_repo_to_date = f"git reset --hard {commit_to_move_to}"
        print(run_command_with_confirm(reset_repo_to_date, cwd=cwd))
