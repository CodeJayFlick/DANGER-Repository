import os
from typing import List

class SpTokenizer:
    def __init__(self, model_path: str):
        self.processor = None
        try:
            self.load_model(model_path)
        except FileNotFoundError as e:
            print(f"Error: {e}")

    def load_model(self, model_path: str) -> None:
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model path doesn't exist: {model_path}")
        
        model_dir = os.path.abspath(model_path)
        for file in os.listdir(model_dir):
            if file.endswith(".model"):
                self.processor = SpProcessor()
                self.processor.load_model(os.path.join(model_dir, file))
                break
        else:
            raise FileNotFoundError(f"No .model found in: {model_path}")

    def tokenize(self, sentence: str) -> List[str]:
        return [self.processor.tokenize(sentence)]

    def build_sentence(self, tokens: List[str]) -> str:
        return " ".join(tokens)

    def close(self):
        if self.processor is not None:
            self.processor.close()

class SpProcessor:
    def __init__(self):
        pass

    def tokenize(self, sentence: str) -> List[str]:
        # TO DO: implement tokenization logic
        raise NotImplementedError("Tokenize method has to be implemented")

    def build_sentence(self, tokens: List[str]) -> str:
        # TO DO: implement building sentence logic
        raise NotImplementedError("Build Sentence method has to be implemented")

    def close(self):
        pass

    def load_model(self, model_path: str) -> None:
        pass


# Example usage:

tokenizer = SpTokenizer("/path/to/model")
print(tokenizer.tokenize("Hello World!"))
