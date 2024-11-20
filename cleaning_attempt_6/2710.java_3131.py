class DependentServiceConstructor:
    def __init__(self, cls: type, method):
        if not isinstance(cls, type) or not callable(method):
            raise ValueError("cls must be a class and method must be a function")
        self.cls = cls
        self.method = method

    @staticmethod
    def construct(obj, dependencies):
        try:
            return self.method.__get__(obj)(*[dependencies.get(param_type) for param_type in self.method.__code__.co_varnames[1:]])
        except Exception as e:
            raise ServiceConstructionException(f"Error constructing dependent service via {self.method}", e)

class ServiceConstructionException(Exception):
    pass
