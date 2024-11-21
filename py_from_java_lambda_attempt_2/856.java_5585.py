Here is the translation of the given Java code into equivalent Python:

```Python
class GadpModelForDbgengFrameActivationTest:
    def get_stack_pattern(self):
        return PathPattern("Sessions[0].Processes[].Threads[].Stack[]")

    @property
    def model_host(self) -> 'GadpDbgengModelHost':
        return GadpDbgengModelHost()

class GadpDbgengModelHost:
    pass

# You can use the following code to test your classes if you want.
if __name__ == "__main__":
    instance = GadpModelForDbgengFrameActivationTest()
    print(instance.get_stack_pattern())
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. The translation is done in a way to maintain the same functionality and structure as the original code, but it may not be exactly identical due to differences between languages.