Here is the translation of the Java interface ` TraceRegisterContextManager` into a Python class:

```Python
class TraceRegisterContextManager:
    def get_register_context_space(self, address_space: 'AddressSpace', create_if_absent=False):
        pass  # TO DO: implement this method

    def get_register_context_thread_space(self, thread: 'TraceThread', create_if_absent=False):
        pass  # TO DO: implement this method
```

Note that in Python, we don't have a direct equivalent of Java interfaces. Instead, we can define classes with abstract methods (i.e., methods without implementation) to achieve similar functionality.

Also note the use of type hints (`'AddressSpace'` and `'TraceThread'`) which are not enforced at runtime but provide information about the expected types for method parameters.