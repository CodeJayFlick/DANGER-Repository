import torch
import torch.nn as nn
from transformers import BertTokenizer, BertModel


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


tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')

model = TextClassifier()
model.load_state_dict(torch.load('model_weights/', weights_only=True))
model.eval()

# TODO: Change to using file passed in command line

file = 'path/to/directory'

tokenized_file = tokenizer(str(open(file)), truncation=True, padding=True, max_length=512, return_tensors='pt')

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = model.to(device)
print(f'Device: {device}')

with torch.no_grad():
    probs = model(input_ids=tokenized_file['input_ids'].to(device),
                        attention_mask=tokenized_file['attention_mask'].to(device))
    cat_1_probs = probs[:, 1]
    probability = float(cat_1_probs[0].item())
    probability = round(probability * 100, 2)
    print(f'Percent chance that human_test.py is AI generated: {probability}%')
