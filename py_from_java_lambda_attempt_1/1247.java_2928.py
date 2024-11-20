Here is the translation of the Java code to Python:
```
import unittest

class InVmModelForDbgmodelRootAttacherTest(unittest.TestCase):
    def model_host(self) -> 'InVmDbgmodelModelHost':
        return InVmDbgmodelModelHost()

    @unittest.skip
    def test_attach_by_pid_then_resume_interrupt(self) -> None:
        super().test_attach_by_pid_then_resume_interrupt()
```
Note that I used the `@unittest.skip` decorator to equivalent of Java's `@Ignore`, and also removed the `throws Throwable` part as Python does not have a built-in exception handling mechanism like Java.