import time
from gpt4all import GPT4All
model = GPT4All("Meta-Llama-3-8B-Instruct.Q4_0.gguf") # downloads / loads a 4.66GB LLM

start_time = time.time()
max_tokens = 4096

output_name = 'output_ai_test_1.txt'
output_file = open(output_name, 'w')
output_text = ''
with model.chat_session():
    output_generator = model.generate("Write 100 Python scripts about various complicated things. The scripts should not be similar to each other.", max_tokens=max_tokens, streaming=True)
    for token in output_generator:
        print(token, end='')
        output_text += token
output_file.write(output_text)


end_time = time.time()
print(f"Completed generation in {end_time - start_time} seconds, with {max_tokens} max_tokens.")
print(f"If all tokens were generated, ran at {max_tokens / (end_time - start_time)} tokens per second.")