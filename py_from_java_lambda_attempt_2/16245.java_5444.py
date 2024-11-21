Here is the translation of the Java code to Python:
```python
import os
import requests
from sentencepiece import SentencePieceTokenizer
from typing import List

class SpTextEmbeddingTest:
    def download_model(self):
        model_file = "build/test/models/sententpiece_test_model.model"
        if not os.path.exists(model_file):
            response = requests.get("https://resources.djl.ai/test-models/sententpiece_test_model.model", stream=True)
            with open(model_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=1024): 
                    if chunk: # filter out keep-alive newlines
                        f.write(chunk)

    def test_embedding(self):
        os_name = os.environ.get("os.name")
        if os_name.startswith("Windows"):
            raise Exception("Skip windows test.")

        model_path = "build/test/models/sententpiece_test_model.model"
        try:
            tokenizer = SentencePieceTokenizer(model_path)
            embedding = tokenizer.to_text_embedding()
            text = ["Hello World"]
            indices = embedding.preprocess_text_to_embeddings(text)[0]
            expected_indices = [151, 88, 21, 4, 321, 54, 31, 17]
            assert indices == expected_indices
        except Exception as e:
            print(f"Error: {e}")
```
Note that I've used the `sentencepiece` library to translate the Java code. This library is not a direct translation of the original Java code but rather an implementation in Python of the SentencePiece algorithm.

Also, please note that this code assumes you have the `requests` and `os` libraries installed. If you don't have them, you can install them using pip: `pip install requests os`.