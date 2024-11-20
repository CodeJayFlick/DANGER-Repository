import logging

class FunctionInfo:
    def __init__(self, handle: int, name: str, arguments: dict):
        self.handle = handle
        self.name = name
        self.arguments = arguments

    def invoke(self, manager, src: list, dest=None, params: dict) -> int:
        check_devices(src)
        if dest is None:
            return JnaUtils.imperative_invoke(handle, src, [], params).size()
        else:
            result = JnaUtils.imperative_invoke(handle, src, dest, params)
            for i in range(len(result)):
                manager.create(result[i])
            return 0

    def invoke(self, manager: dict, src: list, params: dict) -> list:
        check_devices(src)
        pair_list = JnaUtils.imperative_invoke(handle, src, [], params)
        result = []
        for pair in pair_list:
            if pair[1] != SparseFormat.DENSE:
                result.append(manager.create(pair[0], pair[1]))
            else:
                result.append(manager.create(pair[0]))
        return result

    def get_function_name(self) -> str:
        return self.name

    def get_argument_names(self) -> list:
        return list(self.arguments.keys())

    def get_argument_types(self) -> list:
        return list(self.arguments.values())

def check_devices(src: list):
    if logging.getLogger().isEnabledFor(logging.DEBUG) and len(src) > 1:
        device = src[0].get_device()
        for i in range(1, len(src)):
            if not device.equals(src[i].get_device()):
                logging.warning("Please make sure all the NDArrays are in the same device. You can call toDevice() to move the NDArray to the desired Device.")
