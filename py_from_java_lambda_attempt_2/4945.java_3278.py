Here is the translation of the given Java code into Python:

```Python
class ObjectiveCMethodType:
    CLASS = '+'
    INSTANCE = '-'

    def __init__(self, indicator):
        self.indicator = indicator

    @property
    def indicator(self):
        return self._indicator


# Usage example:
print(ObjectiveCMethodType.CLASS)  # Output: +
print(ObjectiveCMethodType.INSTANCE)  # Output: -
```