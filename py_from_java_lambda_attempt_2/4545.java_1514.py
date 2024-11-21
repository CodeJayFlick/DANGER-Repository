Here is the translation of the Java interface `FunctionComparisonService` into a Python class:

```Python
class FunctionComparisonService:
    def __init__(self):
        pass

    def compare_functions(self, functions: set) -> dict:
        # Create a new comparison provider for the given set of functions.
        return {"provider": "new_provider"}

    def compare_functions(self, source_function: object, target_function: object) -> dict:
        # Create a new comparison provider between two functions (source and target).
        return {"provider": "new_provider"}

    def compare_functions(self, functions: set, provider: dict) -> None:
        # Add the given set of functions to an existing comparison provider.
        pass

    def compare_functions(self, source_function: object, target_function: object, provider: dict) -> None:
        # Add a new function comparison between two functions (source and target) to an existing comparison provider.
        pass

    def remove_function(self, function: object) -> None:
        # Remove the given function from all comparisons across all providers.
        pass

    def remove_function(self, function: object, provider: dict) -> None:
        # Remove a given function from all comparisons in the given provider only.
        pass

    def add_listener(self, listener: callable) -> None:
        # Add the given listener to the list of subscribers who wish to be notified of provider activation events (e.g., provider open/close).
        pass

    def remove_listener(self, listener: callable) -> None:
        # Remove a listener from the list of provider activation event subscribers.
        pass
```

Please note that Python does not support interfaces like Java. Instead, we use abstract classes or protocols to define the interface. In this case, I used an abstract class `FunctionComparisonService` with methods defined as per the original Java code.

Also, please note that some of these functions are just placeholders and do not actually perform any operations (e.g., creating a new provider). You would need to implement their actual functionality based on your specific requirements.