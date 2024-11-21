Here is the translation of the Java code into equivalent Python:

```Python
import numpy as np

class NDUtils:
    def __init__(self):
        pass

    @staticmethod
    def get_shape_from_empty_ndarray_for_reduction_op(shape: tuple, axis: int) -> tuple:
        if shape[axis] == 0:
            raise ValueError("attempt to apply reduction of an empty NDArray")
        
        new_shape = [dim for i, dim in enumerate(shape) if i != axis]
        return tuple(new_shape)

    @staticmethod
    def check_concat_input(list: list):
        arrays = np.array(list)
        if (arrays == 0).all():
            raise ValueError("scalar(zero-dimensional) arrays cannot be concatenated")
        
        dimension = len(arrays[0].shape)
        for array in arrays:
            if len(array.shape) != dimension:
                raise ValueError(f"all the input arrays must have same number of dimensions, but the array at index 0 has {dimension} dimension(s) and the array at index {arrays.tolist().index(array)} has {array.shape[0]} dimension(s)")
```

Note that I used NumPy's `numpy` module to handle multi-dimensional arrays.