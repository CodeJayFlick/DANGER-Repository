"""
This script copies all Python files from specified GitHub repos, and puts them into one 
folder. 
The repos must already be cloned - use old_github_collection.py for that.

GITHUB_REPOS - A list of all the original repos that were cloned. This will be used to find the names of the folders
to read from, and to provide the source in the generated about_samples.csv file. If a repo in this folder has not actually been
cloned, that's OK - it will simply be ignored. That being said, if a repo in this folder was not cloned, but another folder
exists with the same name, then that will break things (the program will assume this folder and repo go together, and will
copy the Python files in this folder, attributing them to that repo).
OUTPUT_FOLDER_NAME - The name of the folder to put everything in.

Version: 1.0
Date: 10-28-2024
Author(s): Anthony S
Notes: This script was used to extract the files on 10-28-2024
"""

import os
import csv
import shutil

import clone_and_extract

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
    if os.path.isdir(clone_and_extract.output_folder_name) and len(os.listdir(clone_and_extract.output_folder_name)) != 0:
        exit(f"{clone_and_extract.output_folder_name} already exists and has items in it! Exiting script.")

    if not os.path.isdir(clone_and_extract.output_folder_name):
        os.mkdir(clone_and_extract.output_folder_name)

    csv_file = open(os.path.join(clone_and_extract.output_folder_name, clone_and_extract.CSV_PATH_NAME), 'w', newline='')
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["Filename","AI","Source"])

    count = 0
    for repo in clone_and_extract.github_repos_to_clone:
        if repo in clone_and_extract.failed_clones:
            continue
        if repo[-1] == "/":
            repo = repo[0:-1]
        folder_name = repo.split("/")[-1]
        if not os.path.isdir(folder_name):
            continue
        all_filepaths = get_all_filepaths(folder_name)
        for path in all_filepaths:
            if len(path) < len(clone_and_extract.extension) or path[-(len(clone_and_extract.extension)):] != clone_and_extract.extension:
                continue
            new_filename = path.replace("/", '__').replace("\\", "__")[:-3] + f"_{count}{clone_and_extract.extension}"
            new_full_filepath = os.path.join(clone_and_extract.output_folder_name, new_filename)
            try:
                shutil.copy(path, new_full_filepath)
            except FileNotFoundError:
                print(f"{path} could not be copied. This is likely because {len(path)=}")
            csv_writer.writerow([new_filename, False, repo])
            count += 1