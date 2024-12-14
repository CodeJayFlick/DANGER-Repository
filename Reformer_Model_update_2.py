from reformer_pytorch.reformer_pytorch import Always

#import Tokenizer
#from huggingface_hub import dataset_info

# -*- The purpose of this model -*-
""" -----------------------------------------------------------------------------------
To be able to handle long sequences of tokenized code samples within
both human and AI generated data sets. In Hugging Faces Reformer,
code samples can be built up to 64000 tokens.

Source: Hugging Face Reformer Documentation: https://huggingface.co/transformers/v3.0.2/model_doc/reformer.html
"""

# Author: Cody Franecki
# Date of Revision: September 27th, 2024

import math
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
import torch.optim as optim
import torch.autograd
from reformer_pytorch import ReformerLM, LSHSelfAttention
import numpy
import transformers
from transformers import ReformerModel, ReformerTokenizerFast
from reformer_pytorch.reversible import ReversibleSequence
import get_model_training_data
import tensorflow as tf
from sklearn.model_selection import train_test_split
import numpy

# Assignment to fetch the dataframe from get_model_training_data
df = get_model_training_data.get_dataframe()
df["msg_type"] = df['label'].map({"human": 0, "ai": 1})
df = df.dropna(subset = ["code_sample", "msg_type"])

# Splitting data into test and trained categories
train_code, test_code, train_labels, test_labels = train_test_split(df["code_samples"], df['msg_type'], test_size = 0.10, random_state = 42)

# Class for Tokenizers
class Tokenizer:
    def __init__(self, max_tokens = 64000):
        self.max_tokens = max_tokens
        self.vocab = {}
        self.inv_vocab = {}
        self.next_token_id = 1

    def fit_on_text(self, texts):
        for _ in texts:
            for char in texts:
                if char not in self.vocab:
                    self.vocab[char] = self.next_token_id
                    self.inv_vocab[self.next_token_id] = char
                    self.next_token_id += 1

    def text_to_sequences(self, texts):
        text_sequences = []
        for _ in texts:
            sequence = [self.vocab.get(char, 0) for char in _]
            text_sequences.append(sequence)
        return text_sequences

    def padding(self, text_sequences):
        for i, seq in enumerate(text_sequences):
            if len(seq) > self.max_tokens:
                text_sequences[i] = seq[self.max_tokens]
            elif len(seq) < self.max_tokens:
                text_sequences[i] = seq + [0] * (self.max_tokens - len(text_sequences))
        return text_sequences

tokenizer = Tokenizer(max_tokens = 64000)
all_text = train_code.tolist() + test_code.tolist()
tokenizer.fit_on_texts(all_text)

train_sequences = tokenizer.text_to_sequences(train_code.tolist())
train_sequences = tokenizer.padding(train_sequences)

test_sequences = tokenizer.text_to_sequences(test_code.tolist())
test_sequences = tokenizer.padding(test_sequences)

train_sequences = torch.tensor(train_sequences, dtype = torch.long())
test_sequences = torch.tensor(test_sequences, dtype = torch.long)

# Class to establish how to load data from the dataloader
class Reformer_Dataset(Dataset):
    def __init__(self, sequences, labels):
        self.sequences = sequences
        self.labels = labels

    def __getitem__(self, idx):
        return self.sequences[idx], self.labels[idx]

    def __len__(self):
        return len(self.sequences)

train_dataset = Reformer_Dataset(train_sequences, train_labels.values)
test_dataset = Reformer_Dataset(test_sequences, test_labels.values)

# Creating a dataloader for training data to load batch samples
train_loader = torch.utils.data.DataLoader(
    train_dataset,
    batch_size = 32, # Converting processed data into batches of 16 for easier processing
    shuffle = True,
    sampler = False,
    num_workers =  0, # Number of CPU Cores to be utilized in your device
    collate_fn = None, # Merges list of samples to form mini-batch of tensors, good for map based dataset
    pin_memory= False, # Copies Tensors into pinned memory
    drop_last = False, # drops last incomplete batch
)

test_loader = torch.utils.data.DataLoader(
    test_dataset,
    batch_size = 32,
    shuffle = False,
    num_workers =  0, # Number of CPU Cores to be utilized in your device
    collate_fn = None, # Merges list of samples to form mini-batch of tensors, good for map based dataset
    pin_memory= False, # Copies Tensors into pinned memory
    drop_last = False, # drops last incomplete batch
)

# Class to implement Local Self Attention mechanism to Reformer
class LocalLSHAttention (nn.Module):
    def __init__ (self,
                  dropout = 0,
                  bucket_size = 64,
                  n_hashes = 8,
                  casual = False,
                  attend_across_buckets = True,
                  random_rotations_per_head = True,
                  drop_for_hash_rate = 0.0,
                  return_attn = False):
        super().__init__()
        self.dropout = nn.Dropout(dropout)
        self.drop_for_hash = nn.Dropout(drop_for_hash_rate)

        self.casual = casual
        self.bucket_size = bucket_size
        self.n_hashes = n_hashes
        self.attend_across_buckets = attend_across_buckets
        self.random_rotations_per_head = random_rotations_per_head
        self.return_attn = return_attn
        self._cache = {}

    """A helper function to compute hash values for input vectors. Similar clusters of vectors will be grouped within
       the same bucket, reducing quadratic complexity within for LSH, as traditionally for linear attention, the
       time complexity is quadratic (O(n^2)), but is now reduced to linear (O(log(n)) """
    def hash_vectors(self, vectors, num_buckets):
        batch_size, seq_len, dim = vectors.shape
        device = vectors.device

        # To decrease any chance of hash misses, take a sample of rotations for each instance of hashing
        assert num_buckets % 2 == 0

        rotation_shape = (
            batch_size if self.random_rotations_per_head else 1,
            dim, # matches input vectors last dimension
            self.n_hashes # number of hash rounds
        )

        random_rotations = torch.randn(*rotation_shape, num_buckets // 2, dtype = vectors.dtype, device = device)

        rotated_vectors = torch.einsum('bnd,dhk->bhkn', vectors, random_rotations)
        rotated_vectors = torch.cat([rotated_vectors, -rotated_vectors], dim = -1)

        # Assigning buckets to find the dimension with the highest value
        buckets = torch.argmax(rotated_vectors, dim = -1)
        return buckets

    def forward(self, x, input_mask = True, input_attn_mask = True, pos_emb = None, **kwargs):
        batch_size, seq_len, dim = x.size()

        assert seq_len % self.bucket_size == 0

        if pos_emb is not None:
            x += pos_emb

        x = F.layer_norm(x, [dim])

        #buckets = torch.randint(0, self.num_buckets, (batch_size, seq_len), device = x.device)
        #buckets = self.drop_for_hash(buckets)

        buckets = self.hash_vectors(x, self.num_buckets)

        if input_mask is not None:
            x *= input_mask.unsqueeze(-1)

        # May need to change later (Only if I need to set casual to true)
        if self.casual:
            casual_mask = torch.tril(torch.ones(seq_len, device = x.device)).unsqueeze(0)
            if input_attn_mask is not None:
                casual_mask = casual_mask * input_attn_mask
            x = x * casual_mask

        # May need to re-implement logic at a later time
        #attention_weights = torch.softmax(torch.bmm(x, x.transpose(1, 2) / (dim ** 0.5), dim = -1))

        #attention_weights = self.dropout(attention_weights)

        #output = torch.bmm(attention_weights, x)

        output = torch.zeros_like(x)

        # Iterating each hash id in order to compute attention within each bucket
        for hash_idx in range():
            round_buckets = buckets[:, hash_idx, :] # Retreives current hash assignment for bucket in current round

        # Iteration of each bucket
        for bucket_id in range():
            bucket_mask = torch.eq(round_buckets, bucket_id) # Mask tokens to the bucket
            if bucket_mask.sum() == 0:
                continue # Skip any empty buckets

            # Applies mask within current bucket
            curr_bucket = x * bucket_mask.unsqueeze(-1)

            # Compute attention weights within the bucket
            #attention_weights = torch.bmm(curr_bucket, curr_bucket.transpose(1, 2) / (dim ** 0.5))
            #attention_weights = torch.softmax(attention_weights, dim = -1)
            attention_weights = torch.softmax(
                torch.bmm(curr_bucket, curr_bucket.transpose(1, 2)) / (dim ** 0.5), dim = -1
            )
            attention_weights = self.dropout(attention_weights)
            #attention_weights = self.dropout(bucket_attention_weights)

            bucket_output = torch.bmm(attention_weights, curr_bucket)

            # Aggregating bucket outputs
            output += bucket_output * bucket_mask.unsqueeze(-1)

        # Returns attention weights
        if self.return_attn:
            return output, attention_weights
        return output

# Class in order to establish full attention within the reformer model by using Query Keys
class FullQKAttention(nn.Module):
    def __init__(self, dropout = 0, casual = 0):
        super().__init__()
        self.casual = casual
        self.dropout = nn.Dropout(dropout)

    def forward(self, qk, v, input_mask = None, input_attn_mask = None, **kwargs):
        a, seq_len, dim = qk.shape
        query_len = seq_len

        q = qk[:, 0:query_len]                  # Extracting query from combined query key
        qk = F.normalize(qk, p = 2, dim = -1).type_as(q)   # Normalizing the values of the query keys

        # Computing Dot-Product Operations by scaling
        dot_product = torch.einsum('bie,bje->bij', q, qk) * (dim ** -0.5)

        # QK attention does not require tokens to be self attentive, therefore masking the diagonal will be necessary
        i = torch.arange(query_len, device = dot_product.device)
        dot_product[:, i, i] = float('-inf')

        # Input Masking for padding long sequence of ai and human written code
        if input_mask is not None:
            mask = input_mask[:, 0:query_len, None] * input_mask[:, None, :]
            dot_product.masked_fill(~mask, float('-inf'))

        # Masking conditional for logits of input sequences of qk attention
        if input_attn_mask is not None:
            input_attn_mask = F.pad(input_attn_mask, (0, seq_len - input_attn_mask.shape[-1]), value = True)
            dot_product.masked_fill_(~input_attn_mask, float('-inf'))

        # Conditional statement for casual
        if self.casual:
            casual_mask = torch.tril(torch.ones_like(dot_product))
            dot_product *= casual_mask

        attention_weights = torch.softmax(dot_product, dim = -1)
        attention_weights = self.dropout(attention_weights)
        output = torch.einsum('bij,bje->bie',attention_weights, v)
        return output, torch.empty(0)

class LSHSelfAttention(nn.Module):
    def __init__(self,
                 dim,                   # Number of Dimensions in LSHSelfAttention
                 head,
                 bucket_size = 64,      # Size of each buckets
                 head_size = 8,
                 casual = False,
                 num_hashes = 8,        # Number of hashes processed
                 #dim_head = None,
                 attn_chunks = None,
                 attend_across_buckets = True,
                 dropout = 0,
                 hidden_act = "Gelu",   # Activation function
                 return_attn = None,
                 **kwargs):
        super.__init__()
        self.dim = dim
        self.head = head
        self.bucket_size = bucket_size
        self.head_size = head_size
        self.casual = casual
        self.num_hashes = num_hashes
        #self.dim_head = dim_head
        self.attn_chunks = attn_chunks
        self.attend_across_buckets = attend_across_buckets
        self.dropout = dropout
        self.hidden_act = hidden_act
        self.return_attn = return_attn

        self.qvk = nn.Linear(dim, 3 * dim, bias = False)
        #self.out = nn.Linear(dim_head, dim)
        self.out = nn.Linear(dim, dim)

    def forward(self, tensor, input_mask = None, **kwargs):
        b, n, d = tensor.size()
        #assert d == self.dim

        qvk = self.to_qvk(tensor).chunk(3, dim = -1)
        q, k, v = map(lambda t: t.reshape(b, n, self.num_heads, self.head_dim).transpose(1, 2), qvk)

        # Normalize Layers
        q, k = F.normalize(q, p = 2, dim = -1), F.normalize(k, p = 2, dim = -1)
        #k = F.normalize(k, p = 2, dim = -1)

        # Attention Scores
        attn_scores = torch.einsum('bhqd,bhkd->bhqk', q, k) / math.sqrt(self.dim_head)

        # Padding by using an input mask
        if input_mask is None:
            attn_scores = attn_scores.masked_fill(input_mask[:, None, None, :] == 0, float("-inf"))
            #default_mask = torch.ones((b, n), dtype = device.bool, device = device)
            #input_mask =

        attention = torch.softmax(attn_scores, dim = -1)
        attention = torch.dropout(attention)
        output = torch.einsum('bhqk,bhkd->bhqd', attention, v)
        output = output.transpose(1, 2).contiguous().reshape(b, n, d)
        return self.out(output)

class Gelu_(nn.Module):
    def forward(self, tensor):
        return tensor * 0.5(1 + torch.tanh(math.sqrt(2 / math.pi) * (tensor + 0.044715 * torch.pow(tensor * 3))))

# Class to split computations of layers into little chunks, reducing imprint
class FeedForward(nn.Module):
    def __init__(self, dim, mult = 4, dropout = 0.1, activation = None):
        activation = nn.Gelu()
        self.net = nn.Sequential(
            nn.Linear(dim, dim * mult),
            activation,
            nn.Dropout(dropout),
            nn.Linear(dim * mult, dim),
            nn.GELU()
        )

    def forward(self, x):
        return self.net(x)

class AbsolutePositionalEmbedding(nn.Module):
    def __init__(self, dim, max_seq_len):
        super().__init__()
        self.emb = nn.Embedding(max_seq_len, dim)

    def forward(self, x):
        t = torch.arange(x.shape[1], device = x.device)
        return self.emb(t)

class FixedPositionalEmbedding(nn.Module):
    def __init__(self, dim, max_seq_len):
        super().__init__()
        self.dim = dim
        self.max_seq_len = max_seq_len

        # Precomputes fixed positional embeddings
        inv_freq = 1.0 / (10000 ** (torch.arange(0, dim, 2).float() / dim))
        position = torch.arange(0, max_seq_len).unsqueeze(1).float()
        sinusoid = position * inv_freq
        pos_emb = torch.zeros(max_seq_len, dim)
        pos_emb[:, 0::2] = torch.sin(sinusoid)
        pos_emb[:, 1::2] = torch.sin(sinusoid)

        self.register_buffer('pos_emb', pos_emb)

    def forward(self, x, features = None):
        seq_len = x.size(1)
        assert seq_len <= self.max_seq_len

        pos_emb = self.pos_emb[:seq_len, :].unsqueeze(0)
        x = x + pos_emb

        if features:
            token_count = features.get('token_count', None)
            unique_token_count = features.get('unique_token_count', None)

            if token_count is not None:
                x[:, :, 0] += token_count.unsqueeze(1)
            if unique_token_count is not None:
                x[:, :, 0] += unique_token_count.unsqueeze(1)

            return x

class ReversibleLayer(nn.Module):
    def __init__(self, f, g):
        super().__init__()
        self.f = f
        self.g = g

    def forward(self, x1, x2, **kwargs):
        y1 = x1 + self.f(x2, **kwargs)
        y2 = x2 + self.f(y1, **kwargs)
        return y1, y2

    def backward(self, y1, y2, **kwargs):
        x2 = y2 + self.f(y1, **kwargs)
        x1 = y1 + self.f(y2, **kwargs)
        return x2, x1

# Creating the class that will execute the Reformer Model
class Reformer(torch.nn):
    def __init__(self,
                 num_tokens,
                 dim,
                 depth,
                 max_seq_len,
                 heads=8,
                 dim_head=64,
                 bucket_size = 64,
                 num_hashes=4,
                 ff_chunks = 100,
                 ff_mult=4,
                 ff_dropout=0.1,
                 post_att_dropout = 0.1,
                 absolute_position_emb = True,
                 fixed_position_emb = False,
                 num_classes = 2): # Binary Classification for AI and Human
        super().__init__()
        #self.batch_size = batch_size
        #self.dim = dim
        #self.depth = depth
        #self.d_model = d_model
        #self.d_ff = d_ff
        #self.num_hashes = num_hashes
        #self.num_buckets = num_buckets
        #self.max_len = max_len
        self.token.emb = nn.Embedding(num_tokens, dim)

        # positional embedding
        if absolute_position_emb:
            self.pos_emb = AbsolutePositionalEmbedding(dim, max_seq_len)
        elif fixed_position_emb:
            self.pos_emb = FixedPositionalEmbedding(dim, max_seq_len)
        else:
            self.pos_emb = nn.Always(0)

        # Reformer Core Including Reversible layers
        self.layers = nn.ModuleList([
            ReversibleLayer(
                f = LSHSelfAttention(dim, heads, bucket_size, num_hashes, dropout = post_att_dropout),
                g = FeedForward(dim, mult = ff_mult, dropout = ff_dropout)
            )
            for _ in range(depth)
        ])

        self.norm = nn.LayerNorm(dim)
        self.classifier = nn.Linear(dim, num_classes)

    def forward(self, x):
        x = self.token_emb(x)
        x = x + self.pos_emb(x)

        # Doubling the tensor for the reversible layers
        x = torch.cat([x, x], dim = -1)

        # Passing through reversible layers
        for layers in self.layers:
            x = layers(x.chunk(2, dim = -1)) # Splits chunks into two

        # Merge output of reversible layers
        x1, x2 = x
        x = self.norm((x1 + x2) / 2)

        return self.classifier(x.mean(dim = 1))

class Train_Pipeline:
    def __init__(self, model, train_loader, test_loader, criterion, optimizer, device = "cpu"):
        self.model = model.to(device)
        self.train_loader = train_loader
        self.test_loader = test_loader
        self.criterion = criterion
        self.optimizer = optimizer
        self.device = device

    def train_epochs(self, epoch):
        self.model.train()
        total_loss = 0
        correct = 0
        total = 0

        for inputs, labels in self.train_loader:
            inputs, labels = inputs.to(self.device), labels.to(self.device)
            self.optimizer.zero_grad()

            # Forward Pass
            outputs = self.model(inputs)
            loss = self.criterion(outputs, labels)

            # Backwards Pass
            loss.backward()
            self.optimizer.step()

            # Metric computation
            total_loss += loss.item()
            correct += (outputs.argmax(dim = 1) == labels).sum().item()
            total += labels.size(0)

        accuracy = correct / total
        avg_loss = total_loss / len(self.train_loader)

        print(f"Epoch {epoch+1}:\n\t Train Accuracy: {accuracy:.4f},\n\t Train Loss: {avg_loss:.4f}\n")
        return accuracy, avg_loss

    def evaluate(self):
        self.model.eval()
        total_loss = 0
        correct = 0
        total = 0

        with torch.no_grad():
            for inputs, labels in self.test_loader:
                inputs, labels = inputs.to(self.device), labels.to(self.device)

                # Forward Pass
                outputs = self.model(inputs)
                loss = self.criterion(outputs, labels)

                # Metric computations
                total_loss += loss.item()
                correct += (outputs.argmax(dim = 1) == labels).sum().item()
                total += labels.size(0)

            accuracy = correct / total
            avg_loss = total_loss / len(test_loader)

            print(f"Test Accuracy: {accuracy:.4f}, Test Loss: {avg_loss:.4f}")
            return accuracy, avg_loss

    def train(self, epochs):
        history = {"Train Accuracy": [], "Train Loss": [], "Test Accuracy": [], "Test Loss": []}

        for epoch in range(epochs):
            train_accuracy, train_loss = self.train_epochs(epoch)
            test_accuracy, test_loss = self.evaluate()

            history['Train Accuracy'].append(train_accuracy)
            history['Train Loss'].append(train_loss)
            history['Test Accuracy'].append(test_accuracy)
            history['Test Loss'].append(test_loss)

        return history

# Model initialization
model = Reformer(
    num_tokens=tokenizer.next_token_id,
    dim=512,
    depth=6,
    max_seq_len=64000,
    heads=8,
    dim_head=64,
    bucket_size=64,
    num_hashes=4,
    ff_mult=4,
    ff_dropout=0.1,
    post_att_dropout=0.1
)

# Define optimizer and loss function
optimizer = optim.AdamW(model.parameters(), lr=3e-4)
criterion = nn.CrossEntropyLoss()

# Device setup
device = "cuda" if torch.cuda.is_available() else "cpu"

# Initialize training pipeline
pipeline = Train_Pipeline(model, train_loader, test_loader, criterion, optimizer, device=device)

# Train the model
history = pipeline.train(epochs=10)
