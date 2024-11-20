Here is the translation of the given Java interface into a Python equivalent:

```Python
class ContextChange:
    def apply(self, walker: 'ParserWalker', debug: 'SleighDebugLogger') -> None:
        pass  # Implement this method in your subclass.

    def restore_xml(self, parser: 'XmlPullParser', lang: 'SleighLanguage') -> None:
        pass  # Implement this method in your subclass.
```

Note that Python does not have a direct equivalent to Java's interface. Instead, we define a class with abstract methods (methods without implementation). The `pass` statement is used as a placeholder for the actual implementation of these methods.

The type hints are added using the `->` syntax and single quotes `'`. This indicates that the method takes two parameters (`walker` and `debug`) and returns nothing.