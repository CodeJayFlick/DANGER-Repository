import io

class AbstractMultPointReader:
    def __init__(self):
        pass

    def has_next_time_value_pair(self, full_path: str) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next_time_value_pair(self, full_path: str) -> 'TimeValuePair':
        raise NotImplementedError("Subclasses must implement this method")

    def get_all_paths(self) -> set[str]:
        raise NotImplementedError("Subclasses must implement this method")


class TimeValuePair:
    pass


def deprecated_method(func):
    def wrapper(*args, **kwargs):
        print(f"DEPRECATED: {func.__name__} is not supported")
        return None
    return wrapper

@deprecated_method
def has_next_time_value_pair(self) -> bool:
    return False

@deprecated_method
def next_time_value_pair(self) -> 'TimeValuePair':
    return None

@deprecated_method
def current_time_value_pair(self) -> 'TimeValuePair':
    return None
