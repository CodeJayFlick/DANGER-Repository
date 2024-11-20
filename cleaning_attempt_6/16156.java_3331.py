import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from sklearn.metrics import accuracy_score
from torch.utils.data import Dataset, DataLoader
from torch.nn.utils.rnn import pad_sequence
import numpy as np

class StanfordMovieReviewDataset(Dataset):
    def __init__(self, data, tokenizer, max_len):
        self.data = data
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        text = self.data.iloc[idx, 0]
        label = self.data.iloc[idx, 1]

        encoding = self.tokenizer.encode_plus(
            text,
            add_special_tokens=True,
            max_length=self.max_len,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt'
        )

        return {
            'input_ids': torch.tensor(encoding['input_ids'].flatten()),
            'attention_mask': torch.tensor(encoding['attention_mask'].flatten()),
            'labels': torch.tensor(label)
        }

def train(model, device, data_loader):
    model.train()
    total_loss = 0
    for batch in data_loader:
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels = batch['labels'].to(device)

        optimizer = torch.optim.Adam(model.parameters(), lr=1e-5)
        loss_fn = torch.nn.CrossEntropyLoss()

        optimizer.zero_grad()
        outputs = model(input_ids, attention_mask)
        loss = loss_fn(outputs, labels)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()

    return total_loss / len(data_loader)

def evaluate(model, device, data_loader):
    model.eval()
    predictions = []
    actuals = []

    with torch.no_grad():
        for batch in data_loader:
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)

            outputs = model(input_ids, attention_mask)
            _, predicted = torch.max(outputs.scores, 1)
            predictions.extend(predicted.cpu().numpy())
            actuals.extend(labels.cpu().numpy())

    return accuracy_score(actuals, predictions)

def main():
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    # Load pre-trained model and tokenizer
    model_name = "bert-base-uncased"
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    tokenizer = AutoTokenizer.from_pretrained(model_name)

    # Load dataset
    data_path = "path_to_your_dataset.csv"  # Replace with your actual path
    data = pd.read_csv(data_path, encoding='utf-8')

    # Split into training and validation sets
    train_data, val_data = train_test_split(data, test_size=0.2)

    # Create datasets for training and validation
    train_dataset = StanfordMovieReviewDataset(train_data, tokenizer, 512)
    val_dataset = StanfordMovieReviewDataset(val_data, tokenizer, 512)

    # Create data loaders for training and validation
    batch_size = 32
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

    # Train the model
    epochs = 5
    total_loss = []
    for epoch in range(epochs):
        loss = train(model.to(device), device, train_loader)
        print(f"Epoch {epoch+1}, Loss: {loss:.4f}")
        total_loss.append(loss)

    # Evaluate the model on validation set
    accuracy = evaluate(model.to(device), device, val_loader)
    print(f"Validation Accuracy: {accuracy:.4f}")

if __name__ == "__main__":
    main()
