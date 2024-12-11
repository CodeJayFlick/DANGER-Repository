"""
This script allows generating AI code using an LLM through the Python library GPT4All. 

To generate unique code, the model translates human-written code from another language,
using the input files in a given folder.

Parameters:
- folder_to_translate_from: The folder of code that will be given as a prompt to the model
- output_folder: The folder to write to
- model_name: The name of the model to use. See GPT4All's documentation on what names are usable.
- device: The device to run the model on. Most commonly one of {"cpu", "gpu", "cuda"}. See GPT4All's 
    documentation on what devices are usable.

Notes: Output must be cleaned by clean_ai_data.py.
"""
import csv
import os
from gpt4all import GPT4All

import constants

# Parameters Start

folder_to_translate_from: str = "aggregate_data_java_fixed"
output_folder: str = "py_from_java_lambda_attempt_3"
model_name: str = "Meta-Llama-3-8B-Instruct.Q4_0.gguf"
device : str = "cpu"

previous_generation_folders: list[str] = [""]

# Parameters End


if os.path.isdir(output_folder) and len(os.listdir(output_folder)) != 0:
    exit(f"{output_folder} exists and is not empty. Exiting script.")

print("Current Parameters:") 
print(f"Folder with Human-Written code to translate: {folder_to_translate_from}")
print(f"Folder that output will be written to: {output_folder}")
print(f"Name of LLM that will generate the data: {model_name}")
print(f"Device the LLM will run on: {device}. Main options for this are 'cpu', 'gpu', and 'cuda'. For a full list"
      " of values, see the GPT4ALL documentation.")
print(f"If this script has been interrupted before all data was generated, it is possible to skip all code files "
      "that were already processed. To do this, put the names of the previous output folders in previous_generation_folders.")
if previous_generation_folders:
    print(f"The current contents of previous_generation_folders: {', '.join(previous_generation_folders)}")
else:
    print("There are currently no folder names in previous_generation_folders.")
if input("If you would like to continue, enter 'y'").lower() != "y":
    exit("Script cancelled.")
print("Script starting.")

model = GPT4All(model_name, n_ctx=10000, device="cuda")
max_tokens = 3000

if not os.path.isdir(output_folder):
    os.mkdir(output_folder)

def end_of_path(input_path: str):
    return input_path[max(input_path.rfind("/"), input_path.rfind("\\")) + 1:]

def write_file_with_prompt(filename_to_write: str, prompt: str, do_print=True):
    output_file = open(filename_to_write, 'w')
    output_text = ''
    with model.chat_session():
        output_generator = model.generate(prompt, max_tokens=max_tokens, streaming=True)
        for token in output_generator:
            if do_print:
                print(token, end='')
            output_text += token
    output_file.write(output_text)
    output_file.close()

previously_generated_filenames = []
for folderpath in previous_generation_folders:
    previous_generation_csv_file = open(os.path.join(folderpath, constants.CSV_PATH_NAME), 'r')
    csv_reader = csv.reader(previous_generation_csv_file)
    csv_reader.__next__() # skip first row
    for row in csv_reader:
        # example filepath to be cleaned: py_from_java_lambda_attempt_1/19201.java_3194.py
        code_filename = end_of_path(row[0])
        original_path_end = code_filename.find("_")
        original_path_end = original_path_end if original_path_end != -1 else len(code_filename)
        previously_generated_filenames.append(code_filename[0:original_path_end])
        print(f"{len(previously_generated_filenames)}; {previously_generated_filenames[-1]}")

csv_file_output = open(os.path.join(output_folder, constants.CSV_PATH_NAME), 'w', newline='')
csv_writer = csv.writer(csv_file_output)
csv_writer.writerow(["Filename", "AI", "Source"])

count = 0
for filename in os.listdir(folder_to_translate_from):
    if len(filename) > 4 and filename[-4:] == ".csv":
        continue
    if filename in previously_generated_filenames:
        print(f"Skipping {filename}, as it was previously generated.")
        continue
    print(f"Starting {filename}.")
    try:
        with open(os.path.join(folder_to_translate_from, filename), 'r') as prompt_file:
            prompt = f"The following is a file of code. Translate it to Python.\n\n"
            prompt += prompt_file.read()
            prompt += "\n Once again, translate the above code to Python. Write Python, and only Python."
            new_code_filename = f"{os.path.join(output_folder, filename + f'_{count}.py')}"
            write_file_with_prompt(filename_to_write=new_code_filename, prompt=prompt)
            csv_writer.writerow([new_code_filename, True, model_name])
            csv_file_output.flush()
        count += 1
    except Exception as e:
        print(f"Ran into exception of type {type(e)}: {e}.")
        print(f"Skipping {filename} as a result.")

