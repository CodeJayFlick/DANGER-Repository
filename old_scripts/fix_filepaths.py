exit("Unused script.")

import csv
import os
import shutil
import constants

folder_path = "aggregate_data_java"
new_folder_path = "aggregate_data_java_fixed"
new_about_samples_name = "new_about_samples.csv"

assert not os.path.exists(new_folder_path) or not os.listdir(new_folder_path) # Will not overwrite
if not os.path.exists(new_folder_path):
    os.mkdir(new_folder_path)

csv_read_file = open(os.path.join(folder_path, constants.CSV_PATH_NAME), 'r')
csvreader = csv.reader(csv_read_file)

csv_write_file = open(os.path.join(new_folder_path, new_about_samples_name), 'w', newline='')
csvwriter = csv.writer(csv_write_file)

csvwriter.writerow(["Filename", "AI", "Source", "Comments"])

count = 0
csvreader.__next__() # skip first row
for row in csvreader:
    filename, isAI, source = row
    new_filename = f"{count + 1}.java"
    try:
        shutil.copy(os.path.join(folder_path, filename), os.path.join(new_folder_path, new_filename))
        csvwriter.writerow([new_filename, isAI, source, filename])
    except FileNotFoundError:
        input(f"We've encountered a FileNotFoundError with source path length of {len(os.path.join(folder_path, filename))} characters."
              "Enter anything to continue.")
    count += 1
