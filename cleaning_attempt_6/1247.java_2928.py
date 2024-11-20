import unittest

class InVmModelForDbgmodelRootAttacherTest(unittest.TestCase):
    def model_host(self) -> 'InVmDbgmodelModelHost':
        return InVmDbgmodelModelHost()

    @unittest.skip
    def test_attach_by_pid_then_resume_interrupt(self) -> None:
        super().test_attach_by_pid_then_resume_interrupt()
