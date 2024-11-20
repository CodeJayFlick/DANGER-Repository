Here is the translation of the Java code into Python:

```Python
import torch
from typing import List, Dict, Any

class IValueUtils:
    def __init__(self):
        pass

    @staticmethod
    def forward(block: 'PtSymbolBlock', inputs: List['NDArray'], is_train: bool) -> List['NDArray']:
        i_values = [IValue.from_ndarray(nd_array) for nd_array in inputs]
        result = torch.jit.fork().module_forward(block.handle, [i_value.value for i_value in i_values], not is_train)
        return [torch.tensor(result)]

    @staticmethod
    def forward_symbol_block(block: 'PtSymbolBlock', *inputs: Any) -> IValue:
        handles = [input_.value for input_ in inputs]
        return IValue(torch.jit.fork().module_forward(block.handle, handles, False))

    @staticmethod
    def add_to_map(map_: Dict[str, int], key: str, list_: List[Dict[str, Any]]) -> int:
        if not map_.get(key):
            list_.append({})
            return len(list_) - 1
        else:
            return map_[key]

    @staticmethod
    def get_inputs(nd_list: List['NDArray']) -> List[IValue]:
        outputs = []
        index_map = {}
        for array in nd_list:
            name = array.name
            if name and '.' in name:
                strings = name.split('.', 1)
                index = IValueUtils.add_to_map(index_map, strings[0], outputs)
                outputs[index][strings[1]] = array
            elif name and re.match(r'\w+\[]', name):
                index = IValueUtils.add_to_map(index_map, name, outputs)
                outputs[index]['[]'] = array
            else:
                outputs.append({None: array})
        return [IValue.from_ndarray(array) for array in nd_list]

class PtSymbolBlock:
    def __init__(self):
        pass

    @property
    def handle(self) -> Any:
        raise NotImplementedError

class NDArray(torch.Tensor):
    def __init__(self, value: torch.Tensor):
        super().__init__(value)

    @property
    def name(self) -> str:
        return ''

class IValue:
    def __init__(self, value: Any):
        self.value = value

    @staticmethod
    def from_ndarray(nd_array: 'NDArray') -> 'IValue':
        raise NotImplementedError

    @staticmethod
    def list_from(arrays: List['PtNDArray']) -> 'IValue':
        raise NotImplementedError

    @staticmethod
    def string_map_from(map_: Dict[str, Any]) -> 'IValue':
        raise NotImplementedError
```

Note that this translation is not a direct conversion from Java to Python. It's more of an interpretation of the code in terms of Python syntax and semantics.