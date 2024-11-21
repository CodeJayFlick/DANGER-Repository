import inspect
from functools import wraps

class ProxyUtilities:
    @staticmethod
    def are_same_method(m1: object, m2: object) -> bool:
        if not isinstance(m1, inspect.Method) or not isinstance(m2, inspect.Method):
            return False
        
        if m1.__name__ != m2.__name__:
            return False

        if m1.return_annotation != m2.return_annotation:
            return False

        if list(m1.parameters.values()) != list(m2.parameters.values()):
            return False

        return True

    @staticmethod
    def get_super_method_handle(method: object) -> callable:
        return method.__get__(None, type)

    @staticmethod
    def compose_on_delegate(iface: type, delegate: object, mixins: list[type], lookup: dict):
        all_iface = [iface] + mixins
        
        class ComposedHandler:
            def __init__(self, delegate: object, lookup: dict):
                self.delegate = delegate
                self.lookup = lookup

            def invoke(self, proxy: object, method: callable, args: list) -> any:
                if inspect.ismethod(method) and isinstance(method.__self__, type(delegate)):
                    handle = self.lookup[method]
                    return handle.bind_to(self.delegate).invoke_with_args(args)
                elif not method.__isabstractmethod__():
                    raise ValueError(f"Delegate must implement abstract methods from all mixins. Missed: {method}")
                else:
                    mh = ProxyUtilities.get_super_method_handle(method)
                    return mh.bind_to(proxy).invoke_with_args(args)

        handler = ComposedHandler(delegate, lookup)
        
        return type('Proxy', (object,), {'__call__': lambda self, *args, **kwargs: handler.invoke(self, methodcaller(getattr(type(self).__name__, 'method'), args), args)})

def methodcaller(name):
    def caller(*args, **kwds):
        return getattr(delegate, name)(*args, **kwds)
    return caller

class MethodHandle:
    pass
