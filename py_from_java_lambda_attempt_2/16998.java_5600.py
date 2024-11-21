Here is the translation of the Java interface `FlushManagerMBean` to a Python class:
```
class FlushManagerMBean:
    def get_number_of_working_tasks(self):
        raise NotImplementedError("Not implemented")

    def get_number_of_pending_tasks(self):
        raise NotImplementedError("Not implemented")

    def get_number_of_working_subtasks(self):
        raise NotImplementedError("Not implemented")

    def get_number_of_pending_subtasks(self):
        raise NotImplementedError("Not implemented")
```
Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we define a class with abstract methods using the `raise NotImplementedError` statement.

Also, I didn't include any licensing information or copyright notices as they are not relevant to this translation exercise.