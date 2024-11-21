import io


class LayerPointReader:
    def __init__(self):
        pass

    def next(self) -> bool:
        # Implement your logic here
        raise NotImplementedError("Method 'next' must be implemented")

    def ready_for_next(self):
        # Implement your logic here
        raise NotImplementedError("Method 'ready_for_next' must be implemented")

    def get_data_type(self) -> str:
        # Implement your logic here
        raise NotImplementedError("Method 'get_data_type' must be implemented")

    def current_time(self) -> int:
        # Implement your logic here
        raise NotImplementedError("Method 'current_time' must be implemented")

    def current_int(self) -> int:
        # Implement your logic here
        raise NotImplementedError("Method 'current_int' must be implemented")

    def current_long(self) -> int:
        # Implement your logic here
        raise NotImplementedError("Method 'current_long' must be implemented")

    def current_float(self) -> float:
        # Implement your logic here
        raise NotImplementedError("Method 'current_float' must be implemented")

    def current_double(self) -> float:
        # Implement your logic here
        raise NotImplementedError("Method 'current_double' must be implemented")

    def current_boolean(self) -> bool:
        # Implement your logic here
        raise NotImplementedError("Method 'current_boolean' must be implemented")

    def current_binary(self) -> bytes:
        # Implement your logic here
        raise NotImplementedError("Method 'current_binary' must be implemented")
