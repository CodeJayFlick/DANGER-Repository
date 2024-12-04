"""
This script copies all Python files from specified GitHub repos, and puts them into one 
folder. 
The repos must already be cloned - use old_github_collection.py for that.

folders_to_clone - A list of all the folders that code should be copied from.
OUTPUT_FOLDER_NAME - The name of the folder to put everything in.
extension - The extension to search for (include the '.')

Version: 1.1
Date: 12-4-2024
Author(s): Anthony S
"""

# Parameters Start

folders_to_extract_from = ["test", "Python"]
output_folder_name : str = 'test_extract_files'
extension : str = '.py'

# Parameters End

import os
import csv
import shutil
from subprocess import check_output
import constants

if not extension.startswith('.'):
    exit("Extension must start with '.', exiting script.")
if not folders_to_extract_from:
    exit("folders_to_extract_from is empty.")
if output_folder_name == '':
    exit("No output folder specified.")
if os.path.isdir(output_folder_name) and len(os.listdir(output_folder_name)) != 0:
    exit(f"{output_folder_name} already exists and has items in it! Exiting script.")
folders_to_extract_from = list(filter(lambda folder_name : print(
    f"WARNING: '{folder_name}' was put in folders_to_extract_from, but does not exist.") if not os.path.isdir(folder_name) else True, 
    folders_to_extract_from))


print("Current Parameters:") 
print(f"Folders that will be extracted from: {', '.join(folders_to_extract_from)}")
print(f"Folder that outut will be written to: {output_folder_name}")
print(f"File extension to extract: {extension}")
if input("If you would like to continue, enter 'y'").lower() != "y":
    exit("Script cancelled.")
print("Script starting.")


def find_git_url(directory: str) -> str:
    current_dir = os.getcwd()
    try:
        os.chdir(directory)
        remote_url = str(check_output("git config --get remote.origin.url"), encoding="utf-8").replace("\n", '')
        return remote_url
    except:
        return directory
    finally:
        os.chdir(current_dir)

def get_all_filepaths(directory: str) -> list[str]:
    result = []
    for f in os.listdir(directory):
        fullpath = os.path.join(directory, f)
        if os.path.isdir(fullpath):
            result += get_all_filepaths(fullpath)
        else:
            result.append(fullpath)
    return result

def extract_files():
    if not os.path.isdir(output_folder_name):
        os.mkdir(output_folder_name)

    csv_file = open(os.path.join(output_folder_name, constants.CSV_PATH_NAME), 'w', newline='')
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["Filename","AI","Source"])

    count = 0
    for folder_name in folders_to_extract_from:
        if not os.path.isdir(folder_name):
            continue
        all_filepaths = get_all_filepaths(folder_name)
        for path in all_filepaths:
            if not path.endswith(extension):
                continue
            new_filename = path.replace("/", '__').replace("\\", "__")[:-3] + f"_{count}{extension}"
            new_full_filepath = os.path.join(output_folder_name, new_filename)
            try:
                shutil.copy(path, new_full_filepath)
            except FileNotFoundError:
                print(f"{path} could not be copied. This is likely because {len(path)=}")
            csv_writer.writerow([new_filename, False, find_git_url(folder_name)])
            count += 1