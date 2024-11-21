Here is the translation of the Java code to Python:
```
class PaperBrigadier:
    def __init__(self):
        raise RuntimeError("PaperBrigadier cannot be instantiated!")

    @staticmethod
    def message(component_like: 'ComponentLike') -> Message:
        return PaperBrigadierProvider.instance().message(component_like)

    @staticmethod
    def component_from_message(message: Message) -> Component:
        return PaperBrigadierProvider.instance().component_from_message(message)
```
Note that I've used Python's type hinting system to indicate the types of the function parameters and return values. This is not strictly necessary, but it can help with code readability and maintainability.

Also, I've kept the same method names as in the original Java code, since they seem to be descriptive enough. If you'd like me to suggest alternative Python-style names for the methods, just let me know!