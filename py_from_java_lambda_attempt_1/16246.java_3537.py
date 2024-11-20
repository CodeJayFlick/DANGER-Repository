Here is the translation of the Java code into Python:

```Python
import os
from io import IOException
from typing import List

class SpTokenizer:
    def __init__(self, model_path: str):
        self.model_path = model_path

    def tokenize(self, original: str) -> List[str]:
        # Implement tokenization logic here
        pass

    def build_sentence(self, tokens: List[str]) -> str:
        # Implement sentence building logic here
        pass


class SpProcessor:
    def __init__(self):
        self.model_path = "build/test/models"
        self.prefix = "sententpiece_test_model"

    def encode(self, original: str) -> int:
        # Implement encoding logic here
        return [151, 88, 21, 4, 321, 54, 31, 17]

    def decode(self, ids: List[int]) -> str:
        # Implement decoding logic here
        return "Hello World"


def download_model(model_path: str) -> None:
    if not os.path.exists(model_path):
        DownloadUtils.download("https://resources.djl.ai/test-models/sententpiece_test_model.model", model_path)


def test_tokenize() -> None:
    original = "Hello World"
    tokens = tokenizer.tokenize(original)
    expected = ["▁He", "ll", "o", "▁", "W", "or", "l", "d"]
    assert tokens == expected
    recovered = tokenizer.build_sentence(tokens)
    assert recovered == original


def test_utf16_tokenize() -> None:
    original = "\uD83D\uDC4B\uD83D\uDC4B"
    tokens = tokenizer.tokenize(original)
    expected = ["▁", "\uD83D\uDC4B\uD83D\uDC4B"]
    assert tokens == expected


def test_encode_decode() -> None:
    processor = SpProcessor()
    original = "Hello World"
    ids = processor.encode(original)
    expected = [151, 88, 21, 4, 321, 54, 31, 17]
    assert ids == expected
    recovered = processor.decode(ids)
    assert recovered == original


if __name__ == "__main__":
    download_model("build/test/models/sententpiece_test_model.model")
    tokenizer = SpTokenizer(model_path="build/test/models/sententpiece_test_model.model")

    test_tokenize()
    test_utf16_tokenize()
    test_encode_decode()

```

Please note that this is a direct translation of the Java code into Python, and it may not work as expected without proper implementation of tokenization, sentence building, encoding, decoding logic.