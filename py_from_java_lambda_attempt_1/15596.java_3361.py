Here is the translation of the given Java code into equivalent Python:

```Python
class BertPretrainingLoss:
    def __init__(self):
        self.bert_next_sentence_loss = BertNextSentenceLoss(0, 0)
        self.bert_masked_language_model_loss = BertMaskedLanguageModelLoss(1, 2, 1)

    @property
    def components(self):
        return [self.bert_next_sentence_loss, self.bert_masked_language_model_loss]

class Pair:
    def __init__(self, first, second):
        self.first = first
        self.second = second

def input_for_component(component_index, labels, predictions):
    return Pair(labels, predictions)

class BertNextSentenceLoss:
    def __init__(self, a, b):
        pass  # No implementation in the given Java code

class BertMaskedLanguageModelLoss:
    def __init__(self, a, b, c):
        pass  # No implementation in the given Java code
```

Note that I did not implement `BertNextSentenceLoss` and `BertMaskedLanguageModelLoss` classes as they were missing their implementations.