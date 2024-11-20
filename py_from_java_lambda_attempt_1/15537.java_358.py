Here is the translation of the Java code into Python:

```Python
import numpy as np

class NDList:
    def __init__(self):
        self.ndarrays = []

    def add(self, ndarray: 'NDArray'):
        self.ndarrays.append(ndarray)

    def get(self, name: str) -> 'NDArray':
        for array in self.ndarrays:
            if array.name == name:
                return array
        return None

    def remove(self, name: str):
        index = 0
        for array in self.ndarrays:
            if array.name == name:
                del self.ndarrays[index]
                return array
            index += 1
        return None

    def contains(self, name: str) -> bool:
        for array in self.ndarrays:
            if array.name == name:
                return True
        return False

    def head(self):
        if len(self.ndarrays) > 0:
            return self.ndarrays[0]
        else:
            raise IndexError("Index out of range")

    def singleton_or_throw(self):
        if len(self.ndarrays) != 1:
            raise IndexError("Incorrect number of elements in NDList")
        return self.ndarrays[0]

    def add_all(self, other: 'NDList') -> 'NDList':
        for array in other.ndarrays:
            self.add(array)
        return self

    def sub_ndlist(self, from_index):
        return NDList([array for i, array in enumerate(self.ndarrays) if i >= from_index])

    def to_device(self, device: str, copy: bool = False) -> 'NDList':
        new_nd_list = NDList()
        for array in self.ndarrays:
            new_array = array.to_device(device, copy)
            new_nd_list.add(new_array)
        return new_nd_list

class NDArray:
    def __init__(self, name: str):
        self.name = name
        self.shape = None
        self.data_type = None

    def get_shape(self) -> tuple:
        return self.shape

    def set_shape(self, shape: tuple):
        self.shape = shape

    def get_data_type(self) -> str:
        return self.data_type

    def set_data_type(self, data_type: str):
        self.data_type = data_type

    def to_device(self, device: str, copy: bool = False) -> 'NDArray':
        # implement this method
        pass

    def encode(self) -> bytes:
        # implement this method
        pass

class NDManager:
    def __init__(self):
        self.ndarrays = []

    def add(self, ndarray: 'NDArray'):
        self.ndarrays.append(ndarray)

    def get_nd_array(self, name: str) -> 'NDArray':
        for array in self.ndarrays:
            if array.name == name:
                return array
        return None

# Usage example:

nd_manager = NDManager()
nd_list1 = NDList()
nd_list2 = NDList()

for i in range(5):
    nd_array = NDArray(f"array_{i}")
    nd_array.set_shape((10, 20))
    nd_array.set_data_type("float32")
    nd_manager.add(nd_array)
    if i < 3:
        nd_list1.add(nd_array)
    else:
        nd_list2.add(nd_array)

print("NDList 1:")
for array in nd_list1.ndarrays:
    print(array.name, array.get_shape(), array.get_data_type())

print("\nNDList 2:")
for array in nd_list2.ndarrays:
    print(array.name, array.get_shape(), array.get_data_type())
```

Please note that this is a simplified translation and you may need to adjust it according to your specific requirements.