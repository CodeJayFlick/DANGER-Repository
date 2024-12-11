# Parameters Start

filenames_to_check: list[str] = [".\\Anthony_code_uploads\\discourse_posts_histogram_chatgpt.py"]
BERT_model_path = "default_BERT_model.pth"
reformer_model_path = ""

# Parameters End

print("Importing torch")
import torch
print("Importing torch.nn")
import torch.nn as nn
print("Importing BertTokenizer and BertModel")
from transformers import BertTokenizer, BertModel
print("Imports Complete")


class TextClassifier(nn.Module):
    def __init__(self, model_name='bert-base-uncased', num_classes=2):
        super(TextClassifier, self).__init__()
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


device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f'Device: {str(device).upper()}\n')

model = TextClassifier()
model = torch.load(BERT_model_path, weights_only=False, map_location=device)
model.eval()

tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')

def run_model(filename: str):
    with open(filename, 'r') as file:
        code_file = file.read()
        code_tokenized = tokenizer(code_file, truncation=True, padding=True, max_length=512,
                                return_tensors='pt')
        
        human_probs = model(input_ids=code_tokenized['input_ids'].to(device),
                        attention_mask=code_tokenized['attention_mask'].to(device))
        cat_1_probs_human = human_probs[:, 1]
        human_probability = float(cat_1_probs_human[0].item())
        human_probability = round(human_probability * 100, 2)
        print(f"BERT evaluation: {filename} has a {human_probability} percent chance of being human-written.")


print("Current Parameters:")
print(f"Files that will be tested: {', '.join(filenames_to_check)}")
print(f"BERT Model Path: {BERT_model_path}")
print(f"Reformer Model Path: {reformer_model_path}")

for filename in filenames_to_check:
    run_model(filename)


