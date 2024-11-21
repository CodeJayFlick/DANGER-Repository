Here is the translation of the given Java code into equivalent Python:

```Python
from typing import Optional, List

class NDIndexFullSlice:
    def __init__(self,
                 min: list,
                 max: list,
                 step: list,
                 to_squeeze: list,
                 shape: dict,
                 squeezed_shape: dict):
        self.min = min
        self.max = max
        self.step = step
        self.to_squeeze = to_squeeze
        self.shape = shape
        self.squeezed_shape = squeezed_shape

    @staticmethod
    def from_index(index, target) -> Optional['NDIndexFullSlice']:
        if not all(isinstance(ie, (int, slice)) for ie in index):
            return None
        
        ellipsis_index = next((i for i, ie in enumerate(index) if isinstance(ie, int)), -1)
        
        ind_dimensions = len(index)
        target_dimensions = len(target)

        if ind_dimensions > target_dimensions:
            raise ValueError(f"The index has too many dimensions {ind_dimensions} for array with {target_dimensions}")

        min_ = [0] * target_dimensions
        max_ = [0] * target_dimensions
        step_ = [1] * target_dimensions
        to_squeeze = []
        
        if ellipsis_index == -1 or ellipsis_index == ind_dimensions:
            for i, ie in enumerate(index):
                add_slice_info(ie, i, target, min_, max_, step_, to_squeeze, shape_)
            
            for _ in range(target_dimensions - ind_dimensions):
                pad_index_all(_, target, min_, max_, step_, shape_, squeezed_shape)
        
        elif ellipsis_index == 0:
            padding_dim = target_dimensions - ind_dimensions
            i = 0
            
            while i < padding_dim:
                pad_index_all(i, target, min_, max_, step_, shape_, squeezed_shape)
                i += 1
            
            for _ in range(ind_dimensions):
                ie = index[i]
                add_slice_info(ie, i + padding_dim, target, min_, max_, step_, to_squeeze, shape_, squeezed_shape)
        
        else:
            padding_dim = target_dimensions - ind_dimensions
            i = 0
            
            while i < ellipsis_index:
                ie = index[i]
                add_slice_info(ie, i, target, min_, max_, step_, to_squeeze, shape_, squeezed_shape)
                i += 1
            
            for _ in range(padding_dim + ellipsis_index):
                pad_index_all(i, target, min_, max_, step_, shape_, squeezed_shape)
            
            for _ in range(ind_dimensions):
                ie = index[i]
                add_slice_info(ie, i - padding_dim, target, min_, max_, step_, to_squeeze, shape_, squeezed_shape)

        squeeze_ = [i for i in to_squeeze]

        return NDIndexFullSlice(min_, max_, step_, squeeze_, shape_.copy(), squeezed_shape.copy())

    @staticmethod
    def add_slice_info(ie: int | slice, i: int, target: dict, min_: list, max_: list, step_: list, to_squeeze: list, shape_: dict) -> None:
        if isinstance(ie, int):
            fixed = NDIndexFixed(ie)
            raw_index = fixed.index
            min_[i] = 0 if raw_index < 0 else raw_index % target[i]
            max_[i] = min_[i] + 1
            step_[i] = 1
            to_squeeze.append(i)
            shape_[i] = 1
        
        elif isinstance(ie, slice):
            sliced = NDIndexSlice(*ie.indices(target[i]))
            raw_min = sliced.min or 0
            min_[i] = 0 if raw_min < 0 else raw_min % target[i]
            max_[i] = min_[i] + (sliced.max - sliced.start) // step_
            step_[i] = sliced.step or 1
            shape_[i] = math.ceil((max_[i] - min_[i]) / step_[i])
        
        elif isinstance(ie, NDIndexAll):
            pad_index_all(i, target, min_, max_, step_, shape_, squeezed_shape)

    @staticmethod
    def pad_index_all(i: int, target: dict, min_: list, max_: list, step_: list, shape_: dict, squeezed_shape: dict) -> None:
        min_[i] = 0
        max_[i] = len(target[i])
        step_[i] = 1
        shape_[i] = len(target[i])
        squeezed_shape.append(len(target[i]))

    def get_min(self):
        return self.min

    def get_max(self):
        return self.max

    def get_step(self):
        return self.step

    def get_to_squeeze(self):
        return self.to_squeeze

    def get_shape(self):
        return self.shape

    def get_squeezed_shape(self):
        return self.squeezed_shape


class NDIndexFixed:
    def __init__(self, index: int):
        self.index = index
```

Note that I've used Python's type hinting to indicate the types of variables and function parameters.