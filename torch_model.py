import sys
import time
import get_model_training_data
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from transformers import BertTokenizer, BertModel
from sklearn.model_selection import train_test_split
from tqdm import tqdm
import matplotlib.pyplot as plt

# Get data as a pandas dataframe. Msg_type is 0 for human code and 1 for AI code.
df = get_model_training_data.get_dataframe()
df['msg_type'] = df['label'].map({'human': 0, 'ai': 1})
msg_label = df['msg_type'].values

# Split the data into training/testing data with only two columns, msg_type and code_sample
train_texts, test_texts, train_labels, test_labels = train_test_split(df['code_sample'], df['msg_type'], test_size=0.2,
                                                                      random_state=42)

tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')

# Tokenize a file to test the trained model on
# Requires files labeled chatgpt_test.py and human_test.py in directory
ai_tokenized = tokenizer(str(open('chatgpt_test.py')), truncation=True, padding=True, max_length=512,
                         return_tensors='pt')  # This file is AI generated
human_tokenized = tokenizer(str(open('human_test.py')), truncation=True, padding=True, max_length=512,
                            return_tensors='pt')  # This file is human generated

# TODO: Figure out how to use larger max lengths (if necessary...)
print('Beginning tokenization...')
start_time = time.time()
train_encodings = tokenizer(list(train_texts), truncation=True, padding=True, max_length=512, return_tensors='pt')
test_encodings = tokenizer(list(test_texts), truncation=True, padding=True, max_length=512, return_tensors='pt')
time_taken = round(time.time() - start_time)
print(f'Finished tokenization in {time_taken} seconds')

train_labels_tensor = torch.tensor(train_labels.values, dtype=torch.long)
test_labels_tensor = torch.tensor(test_labels.values, dtype=torch.long)


class TextDataset(Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        item = {key: val[idx] for key, val in self.encodings.items()}
        item['labels'] = self.labels[idx]
        return item


# Create dataset and dataloader
train_dataset = TextDataset(train_encodings, train_labels_tensor)
test_dataset = TextDataset(test_encodings, test_labels_tensor)

train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=16, shuffle=False)


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


# Instantiate the model, loss function, and optimizer
model = TextClassifier()

criterion = nn.CrossEntropyLoss()
optimizer = optim.AdamW(model.parameters(), lr=2e-5)

# Move the device to the GPU, if available
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = model.to(device)
print(f'Device: {str(device).upper()}\n')
loss_list = []  # For plotting purposes

# Training loop
num_epochs = 10

for epoch in range(num_epochs):
    model.train()
    for batch in tqdm(train_loader, desc=f'Training epoch {epoch + 1}', file=sys.stdout):
        inputs = batch['input_ids'].to(device)
        labels = batch['labels'].to(device)
        attention_mask = batch['attention_mask'].to(device)

        outputs = model(input_ids=inputs, attention_mask=attention_mask)
        loss = criterion(outputs, labels)

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
    loss_list.append(loss.item())
    print(f'Epoch {epoch + 1}, Loss: {loss.item()}\n')

# Model testing section
correct = 0
total = 0
test_loss = 0.0

model.eval()

with torch.no_grad():
    ai_probs = model(input_ids=ai_tokenized['input_ids'].to(device),
                     attention_mask=ai_tokenized['attention_mask'].to(device))
    cat_1_probs_ai = ai_probs[:, 1]
    ai_probability = float(cat_1_probs_ai[0].item())
    ai_probability = round(ai_probability * 100, 2)
    print(f'Percent chance that chatgpt_test.py is AI generated: {ai_probability}%')
    human_probs = model(input_ids=human_tokenized['input_ids'].to(device),
                        attention_mask=human_tokenized['attention_mask'].to(device))
    cat_1_probs_human = human_probs[:, 1]
    human_probability = float(cat_1_probs_human[0].item())
    human_probability = round(human_probability * 100, 2)
    print(f'Percent chance that human_test.py is AI generated: {human_probability}%')

# Disable gradient calculations for testing
with torch.no_grad():
    for batch in tqdm(test_loader, desc='Testing model', file=sys.stdout):
        inputs = batch['input_ids'].to(device)
        labels = batch['labels'].to(device)
        attention_mask = batch['attention_mask'].to(device)

        outputs = model(input_ids=inputs, attention_mask=attention_mask)

        loss = criterion(outputs, labels)
        test_loss += loss.item()

        _, predicted = torch.max(outputs, 1)
        total += labels.size(0)
        correct += (predicted == labels).sum().item()

# Calculate average loss and accuracy
avg_test_loss = test_loss / len(test_loader)
accuracy = 100 * correct / total

print(f'\n\nTest Loss: {avg_test_loss: .4f}, Test Accuracy: {accuracy: .2f}%')

plt.plot(loss_list, marker='o')  # Line chart with markers
plt.title("Line Chart of Loss Value")
plt.xlabel("Epoch")
plt.ylabel("Loss")
plt.grid(True)
plt.show()

torch.save(model.state_dict(), 'model_weights/')
