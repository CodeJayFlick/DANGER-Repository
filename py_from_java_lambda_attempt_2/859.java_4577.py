Here is the translation of the given Java code into equivalent Python:

```Python
class GadpModelForDbgengRootAttacherTest:
    def __init__(self):
        pass

    # NB: testListAttachable fails with OTE  - [] not invalidated

    def model_host(self) -> object:
        return GadpDbgengModelHost()
```

Note that Python does not have direct equivalent of Java's `@Override` annotation. The method overriding is done by providing the same name and parameters as in the parent class, without any explicit indication.

Also note that I used the `-> object` syntax to indicate the return type of the `model_host` method, which is similar to how you would specify a return type in Java using the `throws Throwable`.