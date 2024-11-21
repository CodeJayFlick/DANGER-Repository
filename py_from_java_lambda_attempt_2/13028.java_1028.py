Here's the equivalent Python code:

```Python
class PluggableServiceRegistryException(Exception):
    def __init__(self, pluggable_service_class, already_registered_pluggable_service_class,
                 pluggable_service_replacement_instance_class):
        message = f"{pluggable_service_class.__name__} already has registered instance of type {already_registered_pluggable_service_class.__name__}" \
                   f" which is not a super- or subclass of {pluggable_service_replacement_instance_class.__name__}"
        super().__init__(message)
```

Note that Python doesn't have an exact equivalent to Java's `extends` keyword, so I've simply used the `Exception` class as the base class for our custom exception.