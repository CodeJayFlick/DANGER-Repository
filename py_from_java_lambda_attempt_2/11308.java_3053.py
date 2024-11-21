Here is the translation of the Java code to Python:

```Python
class GTaskResult:
    def __init__(self, group, task, e=None, transaction_id=None):
        self.priority = task.get_priority()
        self.description = task.get_description()
        self.group_description = task.get_group().get_description()
        self.exception = e
        self.transaction_id = transaction_id

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value

    def was_cancelled(self):
        return isinstance(self.exception, CancelledException)

    def get_exception(self):
        return self.exception

    def get_priority(self):
        return self.priority

    def get_group_description(self):
        return self.group_description

    def has_same_transaction(self, result):
        if not result:
            return False
        return SystemUtilities.is_equal(self.transaction_id, result.transaction_id)

    def __str__(self):
        return str(self.description)
```

Note that Python does not have direct equivalent of Java's `package` declaration. Also, the concept of private variables and getter/setter methods is different in Python compared to Java. In Python, we use underscore prefix for internal attributes (like `_description`) and property decorator (`@property`) to create read-only or writeable properties.