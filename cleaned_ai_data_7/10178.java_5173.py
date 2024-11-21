import sys
from abc import ABCMeta, abstractmethod


class ContinuesFactory:
    enabled = False  # Initialize with default value

    def __init__(self):
        pass

    @abstractmethod
    def create(self, type: str, *args) -> object:
        try:
            thing = None
            if not self.enabled:
                thing = type(*args)
            else:
                from cglib import Enhancer
                interceptor = ContinuesInterceptor()
                enhancer = Enhancer()
                enhancer.setSuperclass(type)
                enhancer.setCallback(interceptor)
                thing = enhancer.create()

            return thing

        except Exception as e:
            try:
                exception_handler.handle(e)
            except Exception as t:
                # let the handler supplant the original exception if need be
                e = t

            # wrap so clients don't need try/catch everywhere
            raise


class ContinuesInterceptor:
    def __init__(self, exception_handler):
        self.exception_handler = exception_handler


# Usage example:

if __name__ == "__main__":
    class MyExceptionHandler:
        def handle(self, e: Exception) -> None:
            print(f"Handling exception {e}")

    factory = ContinuesFactory()
    try:
        thing = factory.create("MyClass", "arg1", "arg2")
    except RuntimeError as e:
        print(f"Runtime error occurred: {e}")
