print("Importing transformers")
from transformers import AutoTokenizer, ReformerForSequenceClassification, TrainingArguments, Trainer, AutoConfig, DataCollatorWithPadding
print("Importing numpy")
import numpy as np
print("Importing evaluate")
import evaluate
print("Importing datasets")
from datasets import Dataset, DatasetDict, load_dataset
print("Importing get_model_training_data")
import get_model_training_data
print("Importing train_test_split")
from sklearn.model_selection import train_test_split
print("Importing torch")
import torch
from tqdm import tqdm

from torch.optim import AdamW
from transformers import get_scheduler


print("Imports complete")



df = get_model_training_data.get_dataframe(code_sample_labeled_as_text=True, max_samples=1000, use_numeric_labels=True, label_column_name="labels")
train_df, test_df = train_test_split(df, stratify=df["labels"])

print("train_df: ")
print(train_df)
print("test_df: ")
print(test_df)

train_dataset = Dataset.from_pandas(train_df)
test_dataset = Dataset.from_pandas(test_df)

dataset : DatasetDict = load_dataset("yelp_review_full")
dataset = DatasetDict({"train" : dataset["train"].select(range(100)), "test" : dataset["test"].select(range(50))})
print(dataset)
print(type(dataset))

full_dataset = DatasetDict({"train" : train_dataset, "test" : test_dataset})

full_dataset = dataset


tokenizer = AutoTokenizer.from_pretrained("google/reformer-crime-and-punishment")
tokenizer.pad_token = tokenizer.eos_token
assert tokenizer.pad_token_id == tokenizer.eos_token_id

def tokenize_function(examples):
    return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=512)

tokenized_datasets = full_dataset.map(tokenize_function, batched=True)
small_train_dataset = tokenized_datasets["train"]
small_eval_dataset = tokenized_datasets["test"]

# print("Labels for small_train_dataset: ")
# print(small_train_dataset["labels"])
print("First sample of small_train_dataset: ")
print(small_train_dataset[0])  # Check a single sample

config = AutoConfig.from_pretrained("google/reformer-crime-and-punishment", num_labels=2)
model = ReformerForSequenceClassification.from_pretrained("google/reformer-crime-and-punishment", config=config)

device = torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu")
model.to(device)


optimizer = AdamW(model.parameters(), lr=5e-5)
num_training_steps = len(small_train_dataset) * 3  # 3 epochs
lr_scheduler = get_scheduler("linear", optimizer=optimizer, num_warmup_steps=0, num_training_steps=num_training_steps)


epochs = 3

small_train_dataset = small_train_dataset.rename_column("label", "labels")
small_eval_dataset = small_eval_dataset.rename_column("label", "labels")
small_train_dataset = small_train_dataset.remove_columns(["text"])  # Keeps only 'input_ids', 'attention_mask', and 'labels'
small_eval_dataset = small_eval_dataset.remove_columns(["text"])

small_train_dataset.set_format(type="torch", columns=["input_ids", "attention_mask", "labels"])
small_eval_dataset.set_format(type="torch", columns=["input_ids", "attention_mask", "labels"])


# for epoch in range(epochs):
#     print(f"Epoch {epoch + 1}")
#     model.train()
#     train_loss = 0


#     loop = tqdm(small_train_dataset, leave=True)
#     for batch in loop:
#         # Move data to device
#         batch = {k: v for k, v in batch.items()}
        
#         # Forward pass
#         outputs = model(**batch)
#         loss = outputs.loss
#         logits = outputs.logits
        
#         # Backward pass
#         optimizer.zero_grad()
#         loss.backward()
#         optimizer.step()
#         lr_scheduler.step()
        
#         # Update progress bar
#         train_loss += loss.item()
#         loop.set_description(f"Epoch {epoch + 1}")
#         loop.set_postfix(loss=loss.item())

#     print(f"Training Loss: {train_loss / len(small_train_dataset)}")

#     # Evaluation
#     model.eval()
#     all_predictions = []
#     all_labels = []
#     with torch.no_grad():
#         for batch in small_eval_dataset:
#             batch = {k: v.to(device) for k, v in batch.items()}
#             outputs = model(**batch)
#             predictions = torch.argmax(outputs.logits, dim=-1)
#             all_predictions.extend(predictions.cpu().numpy())
#             all_labels.extend(batch["labels"].cpu().numpy())
    
#     eval_results = accuracy.compute(predictions=all_predictions, references=all_labels)
#     print(f"Validation Accuracy: {eval_results['accuracy']}")















#found documentation and example on how to implement collate_fn method to use in dataloader to
#fix size problem
def collate_fn(batch):
    #back based on stack
    #pretty sure batch size padding is uniform so batching based on stack should be fine
    return{
    "input_ids": torch.stack([torch.tensor(example["input_ids"]) for example in batch]),
        "labels": torch.stack([torch.tensor(example["label"]) for example in batch]),
    }
    #return{"input_ids": input_ids, "labels": labels}


# while True:
#     a = input()
#     if a == "-1":
#         break
#     try:
#         exec(a)
#     except:
#         pass

data_collator = DataCollatorWithPadding(tokenizer)


training_args = TrainingArguments(
    output_dir="test_trainer", 
    eval_strategy="epoch",
    logging_dir="logs",
    logging_strategy="steps",
    logging_steps=10
)

metric = evaluate.load("accuracy")

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    return metric.compute(predictions=predictions, references=labels)

trainer = Trainer(model=model,
                  args=training_args,
                  train_dataset=small_train_dataset,
                  eval_dataset=small_eval_dataset,
                  data_collator=data_collator,
                  tokenizer=tokenizer,
                  compute_metrics=compute_metrics)

trainer.train()


# inputs = tokenizer("Hello, my dog is cute", return_tensors="pt")

# with torch.no_grad():
#     logits = model(**inputs).logits

# predicted_class_id = logits.argmax().item()
# label = model.config.id2label[predicted_class_id]

# print(label)

