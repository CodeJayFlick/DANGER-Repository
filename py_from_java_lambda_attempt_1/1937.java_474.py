Here is the translation of the given Java code into equivalent Python:

```Python
import enum

class EvtCase(enum.Enum):
    pass  # Add your event cases here


def GadpEventHandler(value: EvtCase) -> None:
    """Annotates a method as an event handler for GADP."""
    pass  # Implement the logic of this function
```

Note that Python does not have direct equivalents to Java's annotations, interfaces or enums. The above code is equivalent in terms of functionality but may look different from the original Java code.

Here are some key differences:

- In Python, we use a class `EvtCase` instead of an enum.
- We define a function `GadpEventHandler` with one argument and no return value (similar to a void method in Java).
- The `@Target(ElementType.METHOD)` and `@Retention(RetentionPolicy.RUNTIME)` annotations are not directly equivalent. In Python, we can use docstrings or comments to provide information about the purpose of the function.
- We do not have direct equivalents for Java's interfaces (`public interface`) or classes (e.g., `Gadp`).