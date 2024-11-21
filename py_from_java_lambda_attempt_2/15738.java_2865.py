Here is the translation of the given Java interface into a Python class:

```Python
class PostProcessor:
    def __init__(self):
        pass

    def process_output(self, ctx: object, list: 'NDList') -> object:
        """
        Processes the output NDList to the corresponding output object.

        Args:
            ctx (object): The toolkit used for post-processing.
            list ('NDList'): The output NDList after inference.

        Returns:
            object: The output object of expected type.

        Raises:
            Exception: If an error occurs during processing output.
        """
        pass
```

Note that in Python, we don't have a direct equivalent to Java's interfaces. Instead, we use abstract base classes (ABCs) or protocols. Since the given code is just an interface with no implementation, I've translated it into a simple class without any methods implemented.

Also note that I used type hints for the method parameters and return value as per Python 3.x style.