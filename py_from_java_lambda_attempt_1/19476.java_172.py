Here is the translation of the given Java code into Python:

```Python
class NumberExpressionInfo:
    def __init__(self, expression):
        self.expression = expression

    def get(self, event, integer=False):
        number = self.expression.get_single(event)
        return number if number else 0


# Note: The following classes are not directly translatable to Python,
#       as they seem to be part of a larger framework (Skript) and
#       might require additional setup or imports.
class ArithmeticGettable:
    pass

from org.bukkit.event import Event  # This line is likely incorrect, 
                                      # as it seems that the 'Event' class does not exist in Python's standard library.

Expression = object  # Assuming Expression is a generic interface/class
```