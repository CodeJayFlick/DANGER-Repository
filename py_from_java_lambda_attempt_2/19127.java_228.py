Here is the equivalent Python code:

```Python
class ReferenceNotFoundException(Exception):
    def __init__(self, message):
        super().__init__(message)

def for_reference(ref: str) -> 'ReferenceNotFoundException':
    if isinstance(ref, (str)):
        return ReferenceNotFoundException(f"Ref '{ref}' does not exist")
    elif ref.startswith("refs/heads/"):
        return ReferenceNotFoundException(f"Branch '{ref}' does not exist")
    elif ref.startswith("refs/tags/"):
        return ReferenceNotFoundException(f"Tag '{ref}' does not exist")
    else:
        raise ValueError(f"Invalid reference: {ref}")

```

Note that Python doesn't have a direct equivalent to Java's `@Nonnull` annotation. However, you can use type hints and the `requireNonNull` function from the `functools` module (in Python 3.5+) or implement your own version of it.

Also note that I've simplified the exception messages in the `for_reference` method for brevity's sake. You may want to adjust them according to your specific needs.