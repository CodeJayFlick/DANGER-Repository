import logging
from transformers import BertTokenizer, BertForQuestionAnswering
from typing import Dict

logging.basicConfig(level=logging.INFO)

class BertQaInference:
    def __init__(self):
        pass

    @staticmethod
    def predict() -> str:
        question = "When did BBC Japan start broadcasting?"
        paragraph = """BBC Japan was a general entertainment Channel. 
                    Which operated between December 2004 and April 2006. 
                    It ceased operations after its Japanese distributor folded."""

        tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
        model = BertForQuestionAnswering.from_pretrained('bert-base-uncased')

        inputs = {"question": question, "paragraph": paragraph}
        input_ids = [tokenizer.encode(input["question"], return_tensors="pt")[0]]
        attention_mask = [tokenizer.encode(input["question"], add_special_tokens=True, max_length=512, truncation=True, padding='max_length', return_attention_mask=True)[0][:input_ids[0].shape[-1]]]
        inputs.update({"input_ids": input_ids, "attention_mask": attention_mask})

        outputs = model(**inputs)
        start_positions = torch.argmax(outputs.start_logits) + 1
        end_positions = torch.argmax(outputs.end_logits) + 1

        answer = paragraph[start_positions:end_positions].strip()
        logging.info("Answer: %s", answer)

if __name__ == "__main__":
    BertQaInference.predict()
