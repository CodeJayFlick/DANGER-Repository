import time
import csv
import os
from gpt4all import GPT4All
model = GPT4All("Meta-Llama-3-8B-Instruct.Q4_0.gguf") # downloads / loads a 4.66GB LLM

max_tokens = 3000
with open(r"C:\Users\asegr\OneDrive\Documents\GitHub\DANGER-Repository\aggregate_data_java\bitcoin-wallet__wallet__src__de__schildbach__wallet__ui__monitor__BlockListViewModel.j_15253.java", 'r') as file_obj:
    prompt = file_obj.read()

start_time = time.time()
with model.chat_session():
        print("Here")
        output_generator = model.generate(prompt, max_tokens=max_tokens, streaming=True)
        for token in output_generator:
            print(token, end='')


end_time = time.time()
print(f"Completed generation in {end_time - start_time} seconds, with {max_tokens} max_tokens.")
print(f"If all tokens were generated, ran at {max_tokens / (end_time - start_time)} tokens per second.")