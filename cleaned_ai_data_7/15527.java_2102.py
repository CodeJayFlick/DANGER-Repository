class NDArrayIndexer:
    def __init__(self):
        pass

    @abstractmethod
    def get(self, array: 'NDArray', full_pick: 'NDIndexFullPick') -> 'NDArray':
        pass

    @abstractmethod
    def get(self, array: 'NDArray', full_slice: 'NDIndexFullSlice') -> 'NDArray':
        pass

    def get(self, array: 'NDArray', index: 'NDIndex') -> 'NDArray':
        if index.get_rank() == 0 and array.shape.is_scalar():
            return array.duplicate()
        
        indices = list(index.indices)
        if not indices or len(indices) != 1:
            raise ValueError("get() currently doesn't support more than one boolean NDArray")
        
        if isinstance(indices[0], 'NDIndexBooleans'):
            return array.boolean_mask(((indices[0]).index))
        
        full_pick = NDIndexFullPick.from_index(index, array.shape)
        if full_pick.is_present():
            return self.get(array, full_pick.get())
        
        full_slice = NDIndexFullSlice.from_index(index, array.shape)
        if full_slice.is_present():
            return self.get(array, full_slice.get())
        
        raise ValueError("get() currently supports all, fixed, and slices indices")

    @abstractmethod
    def set(self, array: 'NDArray', full_slice: 'NDIndexFullSlice', value: 'NDArray'):
        pass

    def set(self, array: 'NDArray', index: 'NDIndexBooleans', value: 'NDArray') -> None:
        if len(list(index.indices)) != 1 or not isinstance(indices[0], 'NDIndexBooleans'):
            raise ValueError("get() currently doesn't support more than one boolean NDArray")
        
        array.intern(NDArrays.where(((index).index), value, array))

    def set(self, array: 'NDArray', index: 'NDIndex', value: 'NDArray') -> None:
        if isinstance(index[0], 'NDIndexBooleans'):
            self.set(array, (index[0]), value)
        
        full_slice = NDIndexFullSlice.from_index(index, array.shape)
        if full_slice.is_present():
            self.set(array, full_slice.get(), value)

    @abstractmethod
    def set(self, array: 'NDArray', full_slice: 'NDIndexFullSlice', value: int):
        pass

    def set(self, array: 'NDArray', index: 'NDIndex', value: int) -> None:
        if isinstance(index[0], 'NDIndexBooleans'):
            self.set(array, (index[0]), array.manager.create(value))
        
        full_slice = NDIndexFullSlice.from_index(index, array.shape)
        if full_slice.is_present():
            self.set(array, full_slice.get(), value)

    def set_scalar(self, array: 'NDArray', index: 'NDIndex', value: int) -> None:
        full_slice = NDIndexFullSlice.from_index(index, array.shape)
        if full_slice.is_present() and len(full_slice.shape) == 1:
            self.set(array, full_slice.get(), value)

