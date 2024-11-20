import functools

class ContinuesInterceptor:
    def __init__(self, handler):
        self.handler = handler

    def intercept(self, obj, method, args, proxy):
        try:
            result = proxy.__call__(*args)
        except Exception as e:
            self.handler.handle(e)
        return result
