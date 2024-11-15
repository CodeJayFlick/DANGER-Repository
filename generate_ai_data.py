import time
import csv
import os
from gpt4all import GPT4All


folder_to_translate_from = "aggregate_data_java"
output_folder = "py_from_java_attempt_4"
CSV_PATH_NAME = "about_samples.csv"
model_name = "Meta-Llama-3-8B-Instruct.Q4_0.gguf"

model = GPT4All(model_name, n_ctx=10000, device=None if len(GPT4All.list_gpus()) == 0 else "gpu") # downloads / loads a 4.66GB LLM
max_tokens = 3000

if os.path.isdir(output_folder) and len(os.listdir(output_folder)) != 0:
    exit(f"{output_folder} exists and is not empty. Exiting script.")

if not os.path.isdir(output_folder):
    os.mkdir(output_folder)

# start_time = time.time()
# output_name = 'output_ai_test_1.txt'

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


csv_file = open(os.path.join(output_folder, CSV_PATH_NAME), 'w', newline='')
csv_writer = csv.writer(csv_file)
csv_writer.writerow(["Filename", "AI", "Source"])

count = 0
for filename in os.listdir(folder_to_translate_from):
    if len(filename) > 4 and filename[-4:] == ".csv":
        continue
    print(f"Starting {filename}.")
    with open(os.path.join(folder_to_translate_from, filename), 'r') as prompt_file:
        prompt = f"The following is a file of code. Translate it to Python.\n\n"
        prompt += prompt_file.read()
        prompt += "\n Once again, translate the above code to Python. Write Python, and only Python."
        new_code_filename = f"{os.path.join(output_folder, filename + f'_{count}.py')}"
        write_file_with_prompt(filename_to_write=new_code_filename, prompt=prompt)
        csv_writer.writerow([new_code_filename, True, model_name])
    count += 1

# end_time = time.time()
# print(f"Completed generation in {end_time - start_time} seconds, with {max_tokens} max_tokens.")
# print(f"If all tokens were generated, ran at {max_tokens / (end_time - start_time)} tokens per second.")