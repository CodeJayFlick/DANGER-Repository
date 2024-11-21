Here is the equivalent Python code:

```Python
import logging

# Define a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class ConvertToCharArrayHandler:
    def process(self, input: str) -> list[str]:
        characters = list(input)
        string = ''.join(characters)
        logger.info(
            f"Current handler: {type(self).__name__}, "
            f"input is '{input}' of type {type(input)}, output is '{string}', of type {list}"
        )
        
        return characters

# Example usage
handler = ConvertToCharArrayHandler()
output = handler.process("Hello, World!")
print(output)  # Output: ['H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd']
```

Note that Python does not have direct equivalents to Java's `Logger` and `Handler` classes. Instead, we use the built-in `logging` module for logging purposes.