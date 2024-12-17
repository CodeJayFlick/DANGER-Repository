import os
import pandas as pd
from sklearn.model_selection import train_test_split
import torch
from tqdm import tqdm
from torch.utils.data import Dataset, DataLoader, TensorDataset
import transformers
from transformers import ReformerModel, ReformerTokenizerFast
import get_model_training_data
import tensorflow as tf
import numpy as np
from torch.nn.utils.rnn import pad_sequence

from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

HUMAN_LABEL = 'human'
AI_LABEL = 'ai'

def load_dataframe():
  df = get_model_training_data.get_dataframe()

  print("Original Datagrame:")
  print(df)

#   # Label processing for AI and Human Written code
#   df['label'] = df['label'].str.lower().replace({'false': HUMAN_LABEL, 'true': AI_LABEL, 'no': HUMAN_LABEL, 'yes': AI_LABEL})

  print("\nDataframe after label processing:")
  print(df)

  # Dropping rows in which a label is NaN
  df = df.dropna(subset=['label'])

  # Mapping labels to numeric values
  df['msg_type'] = df['label'].map({HUMAN_LABEL: 0, AI_LABEL: 1})
  return df

df = load_dataframe()
train_df, test_df = train_test_split(df, test_size = 0.2, random_state = 42)

tokenizer = Tokenizer(num_words = 50000)
all_texts = train_df['code_sample'].tolist() + test_df['code_sample'].tolist()
tokenizer.fit_on_texts(all_texts)

import torch.nn as nn
import torch.optim as optim
#from tensorflow.keras.preprocessing.sequence import pad_sequences
from torch.nn.utils.rnn import pad_sequence
# Define chunk size
chunk_size = 32
max_length = 512

# Updated function to pad both input_ids and labels
def prepare_data_loader(data, max_length, chunk_size, pad_label=-1, casual = True):
    input_ids = []
    labels = []

    for item in data:
        # Pad input sequences to max_length
        padded_inputs = pad_sequences(item["input_ids"], maxlen=max_length, padding='post', truncating='post')

        # Pad labels to chunk_size, filling with pad_label
        padded_labels = item["labels"]
        if len(padded_labels) < chunk_size:
            padded_labels = np.pad(padded_labels, (0, chunk_size - len(padded_labels)), constant_values=pad_label)

        # Pad the inputs if necessary to chunk_size
        if len(padded_inputs) < chunk_size:
            padded_inputs = np.pad(padded_inputs, ((0, chunk_size - len(padded_inputs)), (0, 0)), 'constant')

        input_ids.append(torch.tensor(padded_inputs, dtype=torch.long))
        labels.append(torch.tensor(padded_labels, dtype=torch.long))

    # Stack inputs and labels with consistent sizes
    input_ids = torch.stack(input_ids, dim=0)  # [num_samples, chunk_size, max_length]
    labels = torch.stack(labels, dim=0)  # [num_samples, chunk_size]

    return TensorDataset(input_ids, labels)

def create_dataloader(df):
    data = []
    df_reset = df.reset_index(drop = True)

    for i in range(0, len(df), chunk_size):
        chunk_texts = df.iloc[i:i+chunk_size-1, df_reset.columns.get_loc("code_sample")].tolist()
        chunk_labels = df.iloc[i:i+chunk_size-1, df_reset.columns.get_loc("msg_type")].tolist()

        # Convert texts to sequences of token IDs
        input_ids = tokenizer.texts_to_sequences(chunk_texts)

        input_ids = pad_sequences(input_ids, maxlen = max_length, padding = 'post', truncating = 'post')

        chunk = {
            "input_ids": input_ids,
            "labels": chunk_labels
        }
        data.append(chunk) # Appending implementations to the defined dictionary
    return data


# Create train and test data loaders
train_data = create_dataloader(train_df)
test_data = create_dataloader(test_df)

# Prepare the DataLoader
train_dataset = prepare_data_loader(train_data, max_length=max_length, chunk_size=chunk_size)
train_dataloader = DataLoader(train_dataset, batch_size=chunk_size, shuffle=True)

# Define the model
class ReformerDataset(nn.Module):
    def __init__(self, d_model=256, vocab_size=50000, input_size = 1):
        super(ReformerDataset, self).__init__()
        self.embedding = nn.Embedding(vocab_size, d_model)
        self.lstm = nn.LSTM(input_size=d_model, hidden_size=d_model, batch_first=True)
        self.dense = nn.Linear(d_model, d_model)
        self.final_dense = nn.Linear(d_model, vocab_size)
        self.dropout = nn.Dropout(0.2)

    def forward(self, inputs):
        # Expand dimensions for LSTM compatibility
        # inputs = inputs.unsqueeze(-1).float()
        inputs = inputs.squeeze(-1)
         # Check the shape of inputs before embedding

        print(f"Input shape before embedding: {inputs.shape}")

        # Ensure input shape is (batch_size, sequence_length)
        if len(inputs.shape) != 2:
            raise ValueError(f"Expected input shape to be 2D, got {inputs.shape}")

        # Pass through embedding layer
        embedded_inputs = self.embedding(inputs)

        # Ensure the embedded output is (batch_size, sequence_length, d_model)
        print(f"Shape after embedding: {embedded_inputs.shape}")

        # Check if the tensor is 3D (batch_size, sequence_length, d_model)
        if len(embedded_inputs.shape) != 3:
            raise ValueError(f"Expected embedded input shape to be 3D, got {embedded_inputs.shape}")

        # LSTM expects (batch_size, sequence_length, d_model)
        lstm_output, _ = self.lstm(embedded_inputs)

        # Check the output shape of the LSTM (batch_size, sequence_length, d_model)
        print(f"Shape after LSTM: {lstm_output.shape}")


        lstm_output = self.dropout(lstm_output[:, -1, :])  # Use the last output for classification
        dense_output = self.dense(lstm_output)
        output = self.final_dense(dense_output)
        return output

# Initialize the model, loss, and optimizer
model = ReformerDataset()
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=1e-8)

# Set requires_grad=True on the input tensor for autograd tracking
def train(model, train_data, optimizer, num_epochs=100):
    model.train()
    for epoch in range(num_epochs):
        epoch_loss = 0.0
        epoch_accuracy = 0.0
        batch_count = 0

        for inputs, labels in train_data:
          print(inputs.shape)
          print(labels)
          inputs = inputs.long()
          #labels = batch[1]
            #inputs = torch.tensor(batch['input_ids'], requires_grad=True)
            #labels = torch.tensor(batch['labels'])

          optimizer.zero_grad()
          inputs = inputs.float()
          outputs = model(inputs)
          loss = criterion(outputs.view(-1, outputs.size(-1)), labels.view(-1))
          loss.backward()

          # Optional gradient clipping
          torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
          optimizer.step()

          # Calculate accuracy
          _, predicted = torch.max(outputs, 1)
          accuracy = (predicted == labels).float().mean()

          epoch_loss += loss.item()
          epoch_accuracy += accuracy.item()
          batch_count += 1

        avg_loss = epoch_loss / batch_count
        avg_accuracy = epoch_accuracy / batch_count

        if (epoch + 1) % 5 == 0:
            print(f"Epoch {epoch + 1}/{num_epochs}, Loss: {avg_loss:.4f}, Accuracy: {avg_accuracy:.4f}")

# Prepare DataLoader for PyTorch
#train_dataloader = DataLoader(train_data, batch_size=chunk_size, shuffle=True)


train(model, train_dataloader, optimizer)