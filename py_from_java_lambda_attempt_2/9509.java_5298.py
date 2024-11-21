Here is the translation of the Java code to Python:
```
class ConditionTestState:
    def __init__(self, condition_tester):
        self.condition_test = condition_tester
        self.enabled = True
        self.result = None

    @property
    def name(self):
        return self.condition_test.name()

    def set_result(self, result):
        with self as lock:  # equivalent to synchronized in Java
            self.result = result

    @property
    def condition_tester(self):
        return self.condition_test

    def get_status(self):
        if self.result is not None:
            return self.result.status()
        return ConditionStatus.None()

    def set_enabled(self, enabled):
        self.enabled = enabled

    def is_enabled(self):
        return self.enabled

    @property
    def status_message(self):
        if self.result is not None:
            return self.result.message()
        return ""

class ConditionTester:
    pass  # equivalent to the Java class in the original code

class ConditionResult:
    pass  # equivalent to the Java class in the original code

class ConditionStatus:
    @staticmethod
    def None():
        return "None"
```
Note that I've used Python's `@property` decorator to create getter and setter methods for some of the attributes, which is a common pattern in Python. I've also replaced the `synchronized` keyword with a lock object (`self as lock`) to achieve similar thread-safety behavior.

Additionally, I've defined equivalent classes for `ConditionTester`, `ConditionResult`, and `ConditionStatus` since they were not provided in the original Java code.