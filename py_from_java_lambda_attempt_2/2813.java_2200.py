Here is the translation of the given Java code into equivalent Python:

```Python
class DBObjectColumn:
    instances = []

    @classmethod
    def get(cls, column_number):
        while len(cls.instances) <= column_number:
            cls.instances.append(None)
        column = cls.instances[column_number]
        if column is None:
            column = cls(column_number)
            cls.instances[column_number] = column
        return column

    def __init__(self, column_number):
        self.columnNumber = column_number


# Example usage:

DBObjectColumn.get(0)  # This will create the first instance of DBObjectColumn if it doesn't exist already.
DBObjectColumn.get(1)
...
```

Please note that Python does not have a direct equivalent to Java's static keyword. In this translation, I used class methods (`@classmethod`) and an `instances` list as a replacement for Java's static variables.