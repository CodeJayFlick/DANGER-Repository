"""
Info:

This file takes our collected data and puts it into a pandas Dataframe.


Formatting requirements: File named "about_samples.csv" in your code upload folder, with the first column
being the exact filename of each source example in your folder, and the second column being "False" if the code
is human written, and "True" if it is AI generated (this is not case sensitive).

The columns must be seperated by commas, and have no spaces.

Usage:
```
import get_model_training_data
dataframe = get_model_training_data.get_dataframe()
```
----

History:
Created: 10/15/24; Author(s): Anthony Segrest

"""

import pandas as pd
import os
import csv
import time
import random

CODE_UPLOAD_FOLDERS = [
    "Anthony_code_uploads",
    "Cody_code_uploads",
    "Kian_code_uploads",
    "Olivia_code_uploads",
    "Tobias_code_uploads",
    "Will_code_uploads",
    "aggregate_data",
    "cleaning_attempt_6",
    "cleaned_ai_data_7"
]

AI_LABEL = 'ai'
HUMAN_LABEL = 'human'
ABOUT_SAMPLES_PATH = "about_samples.csv"

def _standard_label(input_str: str):
    input_str = input_str.lower().strip()
    if input_str in ["true", 'yes', 'ai']:
        return AI_LABEL
    return HUMAN_LABEL

def _get_text_from_file(path: str):
    paths_to_try = [path, path + ".py"]
    for attempted_path in paths_to_try:
        try:
            with open(attempted_path, 'r') as f:
                return f.read()
        except:
            pass
    print(f"{path} could not be accessed. Most likely, the CSV did not have the exact path.") #TODO: should never happen. this happens when the filename in about_samples.csv is not an exact match of the actual filename

def _get_samples_from_folder(folderpath: str) -> dict[str, str]:
    code_samples : dict[str, str] = dict()

    path_to_samples = os.path.join(folderpath, ABOUT_SAMPLES_PATH)
    samples_file = open(path_to_samples, 'r')
    csv_reader = csv.reader(samples_file)
    for i, row in enumerate(csv_reader):
        if i == 0: # ignore first row:
            continue
        if i % 100 == 0:
            print(f"Starting row {i}")
        code = _get_text_from_file(
            os.path.join(folderpath, row[0]))
        if code is not None: #TODO: this code shouldn't be None. unclear why this is happening (probably misformatting?)
            code_samples[code] = _standard_label(row[1])
        else:
            print("Code was None, somehow.")
        #print(row)
    return code_samples    

def get_dataframe(balance_dataset=True, random_seed=None):
    """
    Returns the dataframe, containing all the specified data.

    If balance_dataset is True, will return the same number of each class, by returning all of the
    class with fewer elements, and a randomly chosen subset of the class with more elements.

    If random_seed is not None, and balance_dataset is True, the above randomization will be done via the 
    specified seed. If random_seed is None, and balance_dataset is True, the randomization will be seeded with time.time().


    """
    code_samples : dict[str, str] = dict()

    for folder in CODE_UPLOAD_FOLDERS:
        print(f"Starting folder: {folder}")
        new_samples = _get_samples_from_folder(folder)
        for code in new_samples:
            code_samples[code] = new_samples[code]

    num_ai_samples = len([code for code in code_samples if code_samples[code] == AI_LABEL])
    num_human_samples = len([code for code in code_samples if code_samples[code] == HUMAN_LABEL])
    print(f"Total: {num_ai_samples} AI-generated code pieces; {num_human_samples} Human-written code samples.")
    if balance_dataset:
        rand = random.Random(x=random_seed if random_seed is not None else time.time())
        samples_to_take = min(num_ai_samples, num_human_samples)
        print(f"To balance the dataset, we are taking {samples_to_take} of each class.")
        chosen_ai_samples = rand.sample([code for code in code_samples if code_samples[code] == AI_LABEL], samples_to_take)
        chosen_human_samples = rand.sample([code for code in code_samples if code_samples[code] == HUMAN_LABEL], samples_to_take)
    else:
        chosen_ai_samples = [code for code in code_samples if code_samples[code] == AI_LABEL]
        chosen_human_samples = [code for code in code_samples if code_samples[code] == HUMAN_LABEL]
    
    df = pd.DataFrame({"label" : [AI_LABEL] * len(chosen_ai_samples) + [HUMAN_LABEL] * len(chosen_human_samples), 
                       "code_sample" : chosen_ai_samples + chosen_human_samples})
    return df
