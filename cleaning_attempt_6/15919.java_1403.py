import logging
from mxnet import nd, autograd
from typing import List, Dict, Tuple

class CachedOp:
    def __init__(self,
                 handle: int,
                 manager: 'MxNDManager',
                 parameters: List['Parameter'],
                 param_indices: List[int],
                 data_indices: List[Tuple[str, int]]) -> None:
        self.parameters = parameters
        self.data_indices = data_indices
        self.param_indices = param_indices
        self.manager = manager

    def forward(self,
                parameter_store: 'ParameterStore',
                data: List[nd.NDArray],
                training: bool) -> List[nd.NDArray]:
        all_inputs_ndarray = [None] * len(self.parameters)
        device = Device(data[0].context)

        for index, param in enumerate(self.param_indices):
            value = parameter_store.get_value(param, device, training)
            if value is None:
                raise ValueError("Failed to find parameter from parameterStore")
            all_inputs_ndarray[index] = value

        for array in data:
            input_name = array.name
            idx = self.index_of(input_name)
            all_inputs_ndarray[idx] = array

        for pair in self.data_indices:
            if all_inputs_ndarray[pair[1]] is None:
                # TODO: Do we need to set default to the input?
                batch_size = data[0].shape[0]
                key = pair[0]
                if not (key == "prob_label" or key == "softmax_label"):
                    logging.warning(f"Input {key} not found, set NDArray to Shape({batch_size}) by default")
                    all_inputs_ndarray[pair[1]] = self.manager.create((batch_size,))
        result = JnaUtils.cached_op_invoke(self.manager, handle, all_inputs_ndarray)
        return [nd.NDArray(x) for x in result]

    def close(self):
        if hasattr(handle, 'getAndSet'):
            pointer = getattr(handle, 'getAndSet', None)(None)
            if pointer is not None:
                self.manager.detachInternal(getattr(self, '_uid'))
                JnaUtils.free_cached_op(pointer)
                self.manager = None

    @staticmethod
    def index_of(input_name: str, position: int) -> int:
        if input_name is None:
            return data_indices[position]
        elif (input_name in data_indices_map):
            return data_indices_map[input_name]
        else:
            raise ValueError(f"Unknown input name: {input_name}, expected inputs: {data_indices_map.keys()}")
