Here's the equivalent Python code:

```Python
class Page:
    AUT_PATH = "src/main/resources/sample-ui/"

    def __init__(self, web_client):
        self.web_client = web_client

    @abstractmethod
    def is_at(self) -> bool:
        pass


# Example usage:
from htmlunit import WebClient

web_client = WebClient()
page = Page(web_client)
```

Note that Python does not have a direct equivalent to Java's `abstract` keyword. Instead, we use the built-in `abc` (Abstract Base Classes) module and define an abstract method using the `@abstractmethod` decorator.

Also note that in Python, it is common practice to include docstrings for functions and classes, which provide documentation about what they do. I have not included these here as you did not ask me to translate them into Python.