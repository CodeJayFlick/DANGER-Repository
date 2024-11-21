Here is the translation of the given Java code into Python:

```Python
import numpy as np
from typing import List

class StackBatchifier:
    def batchify(self, inputs: List[np.ndarray]) -> np.ndarray:
        return np.stack(inputs)

    def unbatchify(self, input_array: np.ndarray) -> List[List]:
        return [input_array[i].tolist() for i in range(input_array.shape[0])]

    def split(self, input_array: np.ndarray, num_parts: int, even_split: bool = True) -> List[np.ndarray]:
        if even_split:
            batch_size = (input_array.shape[0] + num_parts - 1) // num_parts
            return [input_array[i * batch_size:(i + 1) * batch_size].copy() for i in range(num_parts)]
        else:
            batch_size, remainder = divmod(input_array.shape[0], num_parts)
            batches = []
            start_idx = 0
            for _ in range(num_parts):
                end_idx = start_idx + batch_size
                if remainder > 0:
                    end_idx += 1
                    remainder -= 1
                batches.append(input_array[start_idx:end_idx].copy())
                start_idx = end_idx
            return batches

def test_batchify():
    inputs = [np.zeros((10, 11)) for _ in range(5)]
    batchifier = StackBatchifier()
    actual = batchifier.batchify(inputs)
    
    assert len(actual.shape) == 3 and actual.shape[:2] == (5, 10)

def test_unbatchify():
    input_array = np.zeros((20, 11))
    batchifier = StackBatchifier()
    actual = batchifier.unbatchify(input_array.reshape(-1, 2))

    for arrays in actual:
        assert len(arrays) == 2 and arrays[0].shape == (11,) and arrays[1].shape == ()

def test_split_even():
    input_array = np.zeros((20, 11))
    batchifier = StackBatchifier()
    actual = batchifier.split(input_array.reshape(-1, 2), 2)

    for i in range(2):
        assert len(actual[i]) == 2 and actual[i][0].shape == (10, 11) and actual[i][1].shape == (10,)

def test_split_uneven():
    input_array = np.zeros((21, 11))
    batchifier = StackBatchifier()
    actual = batchifier.split(input_array.reshape(-1, 2), 3, False)

    for i in range(2):
        assert len(actual[i]) == 2 and actual[i][0].shape == (7, 11) and actual[i][1].shape == (7,)
    
    last_arrays = actual[2]
    assert len(last_arrays) == 2 and last_arrays[0].shape == (4, 11) and last_arrays[1].shape == (4,)