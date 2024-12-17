# Parameters Start

filenames_to_check: list[str] = [".\\presentation_example_clean_ai_data\\236.java_35.py", # AI
    ".\\presentation_example_clean_ai_data\\1038.java_6.py", #AI
    "clone_github_repos.py", #HUMAN
    "extract_files.py", # HUMAN
    "train_many_models.py", #HUMAN
    ".\\presentation_example_clean_ai_data\\1185.java_30.py", # AI
    ]
BERT_model_path = "bert-base-uncased_finetuned_2.pth"
roberta_model_path = "roberta-base_finetuned.pth"

# Parameters End

print("Importing torch")
import torch
print("Importing torch.nn")
import torch.nn as nn
print("Importing BertTokenizer, BertModel, RobertaTokenizer, RobertaModel")
from transformers import BertTokenizer, BertModel, RobertaTokenizer, RobertaModel
import bert_model, roberta_model
print("Importing regex")
import re
print("Imports Complete")

input("Press 'Enter' to continue the script.")

model_name_regex = re.compile(r"_finetuned(_[0-9]+)?.pth$")

def save_path_to_name(save_path: str) -> str:
    if save_path == "default_BERT_model.pth":
        return 'bert-base-uncased'
    possible_match = model_name_regex.search(save_path)
    if possible_match:
        return save_path[0:possible_match.start()].replace("_ _", "/")
    raise Exception("Model name could not be identified")


# must be in here for deserialization
class TextClassifier(nn.Module):
    def __init__(self, model_name, num_classes=2):
        super(TextClassifier, self).__init__()
        try:
            self.bert = RobertaModel.from_pretrained(model_name)
        except:
            self.bert = BertModel.from_pretrained(model_name)
        self.dropout = nn.Dropout(0.3)
        self.fc1 = nn.Linear(self.bert.config.hidden_size, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc_out = nn.Linear(64, num_classes)
        self.relu = nn.ReLU()

    def forward(self, input_ids, attention_mask):
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        pooled_output = outputs.pooler_output

        x = self.fc1(pooled_output)
        x = self.relu(x)
        x = self.dropout(x)

        x = self.fc2(x)
        x = self.relu(x)
        x = self.dropout(x)

        logits = self.fc_out(x)
        probabilities = nn.functional.softmax(logits, dim=-1)

        return probabilities


bert_model_name = save_path_to_name(BERT_model_path)
roberta_model_name = save_path_to_name(roberta_model_path)

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f'Device: {str(device).upper()}\n')

bert_model_obj = bert_model.TextClassifier(model_name=bert_model_name)
bert_model_obj = torch.load(BERT_model_path, weights_only=False, map_location=device)
bert_model_obj.eval()

roberta_model_obj = roberta_model.TextClassifier(model_name=roberta_model_name)
roberta_model_obj = torch.load(roberta_model_path, weights_only=False, map_location=device)
roberta_model_obj.eval()

bert_tokenizer = BertTokenizer.from_pretrained(bert_model_name)
roberta_tokenizer = RobertaTokenizer.from_pretrained(roberta_model_name)

def run_model(filename: str):
    with open(filename, 'r') as file:
        code_file = file.read()
        for tokenizer, model_obj, name in [(bert_tokenizer, bert_model_obj, "BERT"), (roberta_tokenizer, roberta_model_obj, "Roberta")]:
            code_tokenized = tokenizer(code_file, truncation=True, padding=True, max_length=512,
                                    return_tensors='pt')
            human_probs = model_obj(input_ids=code_tokenized['input_ids'].to(device),
                            attention_mask=code_tokenized['attention_mask'].to(device))
            cat_1_probs_human = human_probs[:, 1]
            human_probability = float(cat_1_probs_human[0].item())
            human_probability = round(human_probability * 100, 2)
            print(f"{name} evaluation: {filename} has a {human_probability} percent chance of being AI generated.")

print("Current Parameters:")
print(f"Files that will be tested: {', '.join(filenames_to_check)}")
print(f"BERT Model Path: {BERT_model_path}")
print(f"RoBERTa Model Path: {roberta_model_path}")

for filename in filenames_to_check:
    run_model(filename)


