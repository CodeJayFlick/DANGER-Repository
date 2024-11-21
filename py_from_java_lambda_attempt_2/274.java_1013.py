Here is the translation of the Java interface `ManagedStackRecorder` into a Python class:

```python
class ManagedStackRecorder:
    def offer_stack_frame(self, added):
        pass  # implement this method in your subclass

    def record_stack(self):
        pass  # implement this method in your subclass

    def get_successor_frame_level(self, successor: int) -> int:
        raise NotImplementedError("Method not implemented")

    def get_trace_stack_frame(self, trace_thread: object, level: int) -> object:
        raise NotImplementedError("Method not implemented")

    def get_target_stack_frame(self, frame_level: int) -> object:
        raise NotImplementedError("Method not implemented")
```

Note that I've kept the method signatures and variable names similar to the original Java code. However, in Python, we don't need explicit type declarations or `public` access modifiers.

Also, since this is an interface (i.e., a contract), I've left the implementation of each method as a placeholder (`pass`) for you to fill in with your own logic when creating a subclass that implements this interface.