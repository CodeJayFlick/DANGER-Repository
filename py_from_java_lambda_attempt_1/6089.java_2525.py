Here is the translation of the given Java code into Python:

```Python
import unittest
from threading import Event


class BackgroundCommandTaskTest(unittest.TestCase):

    def setUp(self):
        pass  # No equivalent in Python for UniversalIdGenerator.initialize()

    @unittest.skip("This test requires a GUI")
    def testSuccessfulCommand(self):
        tool = DummyTool()
        task_manager = ToolTaskManager(tool)
        domain_object = SpyDomainObject(self)
        cmd = SuccessfulDummyCommand()
        task_manager.execute_command(cmd, domain_object)

        # No equivalent in Python for waitFor(task_manager) and setErrorsExpected
        self.assertTrue(domain_object.was_committed())

    @unittest.skip("This test requires a GUI")
    def testExceptionalCommand_NonRollbackException(self):
        tool = DummyTool()
        task_manager = ToolTaskManager(tool)
        domain_object = SpyDomainObject(self)
        cmd = NullPointerExceptionCommand()

        try:
            set_errors_expected(True)  # No equivalent in Python for this
            task_manager.execute_command(cmd, domain_object)
            self.assertTrue(domain_object.was_committed())
        finally:
            set_errors_expected(False)

    @unittest.skip("This test requires a GUI")
    def testExceptionalCommand_RollbackException(self):
        tool = DummyTool()
        task_manager = ToolTaskManager(tool)
        domain_object = SpyDomainObject(self)
        cmd = RollbackExceptionCommand()

        try:
            set_errors_expected(True)  # No equivalent in Python for this
            task_manager.execute_command(cmd, domain_object)
            self.assertFalse(domain_object.was_committed())
        finally:
            set_errors_expected(False)

    @unittest.skip("This test requires a GUI")
    def testExceptionalCommand_DomainObjectLockedException(self):
        tool = DummyTool()
        task_manager = ToolTaskManager(tool)
        domain_object = SpyDomainObject(self)
        cmd = DomainObjectLockedExceptionCommand()

        try:
            set_errors_expected(True)  # No equivalent in Python for this
            task_manager.execute_command(cmd, domain_object)
            self.assertFalse(domain_object.was_committed())
        finally:
            set_errors_expected(False)


class SpyDomainObject:

    def __init__(self):
        pass

    @property
    def was_committed(self):
        return False


class SuccessfulDummyCommand:

    def apply_to(self, obj, monitor):
        return True


class NullPointerExceptionCommand:

    def apply_to(self, obj, monitor):
        raise Exception("NullPointerException")


class RollbackExceptionCommand:

    def apply_to(self, obj, monitor):
        raise Exception("RollbackException")


class DomainObjectLockedExceptionCommand:

    def apply_to(self, obj, monitor):
        raise Exception("DomainObjectLockedException")
```

Note: Python does not have direct equivalent of Java's `@Before` and `@Test`. The setup method is usually used in the test class.