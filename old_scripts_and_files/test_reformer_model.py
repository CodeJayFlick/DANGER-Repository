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
print("Imports complete")


df = get_model_training_data.get_dataframe(code_sample_labeled_as_text=True, max_samples=1000, use_numeric_labels=True)
train_df, test_df = train_test_split(df, stratify=df["label"])

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

# exit()

full_dataset = DatasetDict({"train" : train_dataset, "test" : test_dataset})

full_dataset = dataset


tokenizer = AutoTokenizer.from_pretrained("google/reformer-crime-and-punishment")
tokenizer.pad_token = tokenizer.eos_token
assert tokenizer.pad_token_id == tokenizer.eos_token_id

def tokenize_function(examples):
    return tokenizer(examples["text"], padding="max_length", truncation=True)

tokenized_datasets = full_dataset.map(tokenize_function, batched=True)
small_train_dataset = tokenized_datasets["train"]
small_eval_dataset = tokenized_datasets["test"]

print("Labels for small_train_dataset: ")
print(small_train_dataset["label"])
print("First sample of small_train_dataset: ")
print(small_train_dataset[0])  # Check a single sample

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

config = AutoConfig.from_pretrained("google/reformer-crime-and-punishment", num_labels=2)
model = ReformerForSequenceClassification.from_pretrained("google/reformer-crime-and-punishment", config=config)

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
                  data_collator=collate_fn,
                  tokenizer=tokenizer,
                  compute_metrics=compute_metrics)

trainer.train()


# inputs = tokenizer("Hello, my dog is cute", return_tensors="pt")

# with torch.no_grad():
#     logits = model(**inputs).logits

# predicted_class_id = logits.argmax().item()
# label = model.config.id2label[predicted_class_id]

# print(label)

