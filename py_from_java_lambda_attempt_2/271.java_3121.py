Here is the translation of the Java interface `ManagedMemoryRecorder` to a Python class:

```python
class ManagedMemoryRecorder:
    def offer_process_region(self, region):
        pass  # implementation left out for brevity

    def remove_process_region(self, region):
        pass  # implementation left out for brevity

    def get_trace_memory_region(self, region):
        return None  # or some other default value
```

Note that I've kept the method implementations minimal, as they were in the original Java interface. You would need to fill in the actual logic and behavior for each method based on your specific requirements.

Also, Python does not have a direct equivalent of interfaces like Java's `interface` keyword. Instead, we use abstract base classes (ABCs) or protocols to define a set of methods that must be implemented by any class that inherits from it. In this case, I've simply defined a regular Python class with the same method names as the original interface.