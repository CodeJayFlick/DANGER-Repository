Here is the translation of the given Java code into equivalent Python:

```Python
import torch
from djl import ndarray as ndarray
from djl.ndarray.index import NDIndexBooleans, NDIndexFullPick, NDIndexFullSlice
from djl.ndarray.types import Shape


class PtNDArrayIndexer:
    def __init__(self, manager):
        self.manager = manager

    def get(self, array: ndarray.NDArray, full_pick: NDIndexFullPick) -> ndarray.NDArray:
        return torch.index_select(
            self.manager.from_array(array), 
            dim=full_pick.get_axis(), 
            index=torch.tensor(full_pick.get_indices())
        )

    def get(self, array: ndarray.NDArray, full_slice: NDIndexFullSlice) -> ndarray.NDArray:
        min_val = tuple(full_slice.get_min())
        max_val = tuple(full_slice.get_max())
        step = tuple(full_slice.get_step())

        res = torch.index_select(
            self.manager.from_array(array), 
            dim=0 if len(min_val) == 1 else -1, 
            index=torch.arange(*min_val, *max_val, *step)
        )

        return res.squeeze(tuple(range(len(res.shape))))
    
    def set(self, array: ndarray.NDArray, full_slice: NDIndexFullSlice, value: torch.Tensor):
        target_shape = tuple(full_slice.get_shape())
        
        while len(target_shape) > len(value.shape):
            target_shape = target_shape[1:]
            
        value = value.reshape(*target_shape)
        value = value.broadcast_to(tuple(range(len(array.shape))))
        
        torch.index_fill(
            self.manager.from_array(array), 
            torch.tensor(full_slice.get_min()), 
            torch.tensor(full_slice.get_max()), 
            torch.tensor(full_slice.get_step())
        )
    
    def set(self, array: ndarray.NDArray, indices: NDIndexBooleans, value: torch.Tensor):
        mask = indices.getIndex()
        
        torch.masked_fill(
            self.manager.from_array(array), 
            mask, 
            value
        )

    def set(self, array: ndarray.NDArray, full_slice: NDIndexFullSlice, num_value: float):
        return self.set(array, full_slice, torch.tensor([num_value]))
```

Please note that this is a direct translation of the given Java code into Python. The original Java code seems to be part of some larger project (possibly related to deep learning), and it's not immediately clear what specific functionality these classes are intended to provide or how they should interact with other parts of the system.