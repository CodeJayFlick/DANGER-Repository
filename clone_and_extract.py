"""
This script clones and extracts files from GitHub repos.

github_repos_to_clone - This should be a list of all Github repos to be cloned/extracted from
github_repos_already_cloned - Any repos in here will not be cloned
failed_clones - Any repos in here will not be extracted from

extension - The file extension to extract
date_to_access_string - The date of the repos to access
output_folder_name - the name of the folder to output the extracted files in
CSV_PATH_NAME - the name of the csv file to log files in - should be left as "about_samples.csv"

Notes:
- Repos in github_repos_already_cloned and failed_clones must match
    exactly with github_repos_to_clone, for the script to behave correctly.
    This is partially guaranteed by an assert statement before the script runs.
- No Github repos in github_repos_to_clone can share the same name (as this would make their folder names conflict)

"""

import old_github_collection
import extract_py_files

github_repos_to_clone : list[str] = [
    "https://github.com/PaperMC/Paper",
    "https://github.com/NationalSecurityAgency/ghidra",
    "https://github.com/iluwatar/java-design-patterns",
    "https://github.com/bitcoin-wallet/bitcoin-wallet",
    "https://github.com/SoLegendary/reignofnether",
    "https://github.com/IrisShaders/Iris", # main was not named either main nor master. this script failed as a result
    "https://github.com/Team-xManager/xManager",
    "https://github.com/moneytoo/Player",
    "https://github.com/power721/alist-tvbox",
    "https://github.com/IzzelAliz/Arclight", # main was not named either main nor master. this script failed as a result
    "https://github.com/gyoogle/tech-interview-for-developer",
    "https://github.com/deepjavalibrary/djl",
    "https://github.com/FIRST-Tech-Challenge/FtcRobotController",
    "https://github.com/apache/iotdb",
    "https://github.com/GrimAnticheat/Grim",
    "https://github.com/software-mansion/react-native-svg",
    "https://github.com/in28minutes/master-spring-and-spring-boot",
    "https://github.com/EssentialsX/Essentials", # failed for usual reason
    "https://github.com/aws/serverless-java-container",
    "https://github.com/projectnessie/nessie",
    "https://github.com/SkriptLang/Skript"    
]

github_repos_already_cloned : list[str] = [
    "https://github.com/PaperMC/Paper",
    "https://github.com/NationalSecurityAgency/ghidra",
    "https://github.com/iluwatar/java-design-patterns",
    "https://github.com/bitcoin-wallet/bitcoin-wallet",
    "https://github.com/SoLegendary/reignofnether",
    "https://github.com/IrisShaders/Iris", # main was not named either main nor master. this script failed as a result
    "https://github.com/Team-xManager/xManager",
    "https://github.com/moneytoo/Player",
    "https://github.com/power721/alist-tvbox",
    "https://github.com/IzzelAliz/Arclight", # main was not named either main nor master. this script failed as a result
    "https://github.com/gyoogle/tech-interview-for-developer",
    "https://github.com/deepjavalibrary/djl",
    "https://github.com/FIRST-Tech-Challenge/FtcRobotController",
    "https://github.com/apache/iotdb",
    "https://github.com/GrimAnticheat/Grim",
]

failed_clones : list[str] = [
    "https://github.com/IrisShaders/Iris", # main was not named either main nor master. this script failed as a result
    "https://github.com/IzzelAliz/Arclight", # main was not named either main nor master. this script failed as a result
    "https://github.com/GrimAnticheat/Grim", # same issue
        "https://github.com/EssentialsX/Essentials", # failed for usual reason


]
# Any repos in here will be ignored by extract_py_files

for repo in github_repos_already_cloned:
    assert repo in github_repos_to_clone
for repo in failed_clones:
    assert repo in github_repos_to_clone
assert len(set(map(lambda x : x[x.rfind("/"):], github_repos_to_clone))) == len(github_repos_to_clone)
# The above line checks that no github repos share the same name.



do_cloning = False
do_extract = True

extension = ".java"
date_to_access_string = "2021-10-28" # one day before release date of GitHub Copilot, way before ChatGPT

output_folder_name = "aggregate_data_java"
CSV_PATH_NAME = "about_samples.csv"

if __name__ == "__main__":
    if do_cloning:
        old_github_collection.clone_repos()
    if do_extract:
        if input("Do you want to continue to file extraction? Enter 'y' to continue, and anything else to quit: ") != 'y':
            exit("Script exiting.")
        extract_py_files.extract_files()


