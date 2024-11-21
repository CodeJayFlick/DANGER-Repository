class ProvidesTargetViaLaunchSpecimen:
    def __init__(self):
        pass

    def get_test(self) -> 'AbstractDebuggerModelTest':
        # Probably just return self
        raise NotImplementedError("get_test must be implemented")

    def obtain_target(self) -> TargetObject:
        launcher = self.get_test().find_launcher()
        assert launcher is not None, "No launcher found"
        specimen = self.get_launch_specimen()
        wait_acc(launcher)
        launcher.launch(specimen.get_launcher_args())
        return retry_for_process_running(specimen, self.get_test())

    def get_launch_specimen(self) -> 'DebuggerTestSpecimen':
        # Probably just return something
        raise NotImplementedError("get_launch_specimen must be implemented")

def wait_acc(launcher):
    pass

def retry_for_process_running(specimen, test):
    pass

class TargetObject:
    pass

class AbstractDebuggerModelTest:
    def find_launcher(self) -> 'TargetLauncher':
        # Probably just return something
        raise NotImplementedError("find_launcher must be implemented")

    def get_test_specimen(self) -> 'DebuggerTestSpecimen':
        # Probably just return something
        raise NotImplementedError("get_test_specimen must be implemented")
