import asyncio
from abc import ABC, abstractmethod


class AbstractDebuggerModelLauncherTest:
    def __init__(self):
        self.m = None  # This variable seems to be used in various methods but its type and initialization are not provided.

    async def test_launcher_is_where_expected(self):
        expected_launcher_path = await self.get_expected_launcher_path()
        if expected_launcher_path is None:
            return
        launcher = await self.find_launcher()
        assert expected_launcher_path == launcher.path

    async def get_expected_launcher_path(self):
        # This method seems to be abstract and should be implemented in the subclass.
        pass

    @abstractmethod
    async def get_expected_launcher_parameters(self):
        pass

    async def test_launch_parameters(self):
        expected_parameters = await self.get_expected_launcher_parameters()
        if expected_parameters is None:
            return
        launcher = await self.find_launcher()
        await self.run_test_launch_parameters(launcher, expected_parameters)

    async def run_test_launch_parameters(self, launcher: 'TargetLauncher', expected_parameters: dict) -> None:
        # This method seems to be waiting for some process or attribute.
        pass

    async def test_launch(self):
        m = self.m  # Assuming this is the instance of a class that has build and find_launcher methods
        if m is None:
            return
        launcher = await self.find_launcher()
        listener = ProcessCreatedDebugModelListener()  # This seems to be an inner class.
        m.add_model_listener(listener)
        await self.run_test_launch(launcher)

    async def run_test_launch(self, launcher: 'TargetLauncher') -> None:
        # This method seems to be waiting for some process or attribute.
        pass

    async def test_launch_then_detach(self):
        if not hasattr(m, "has_detachable_processes"):
            return
        m.build()
        launcher = await self.find_launcher()
        await self.run_test_launch(launcher)
        await self.run_test_detach()

    async def run_test_detach(self) -> None:
        # This method seems to be waiting for some process or attribute.
        pass

    async def test_launch_then_kill(self):
        if not hasattr(m, "has_killable_processes"):
            return
        m.build()
        launcher = await self.find_launcher()
        await self.run_test_launch(launcher)
        await self.run_test_kill()

    async def run_test_kill(self) -> None:
        # This method seems to be waiting for some process or attribute.
        pass

    async def test_launch_then_resume(self):
        if not hasattr(m, "has_killable_processes"):
            return
        m.build()
        launcher = await self.find_launcher()
        await self.run_test_launch(launcher)
        await self.run_test_resume_terminates()

    async def run_test_resume_terminates(self) -> None:
        # This method seems to be waiting for some process or attribute.
        pass

    async def test_launch_shows_in_process_container(self):
        if not hasattr(m, "has_process_container"):
            return
        m.build()
        launcher = await self.find_launcher()
        await self.run_test_launch(launcher)
        await asyncio.create_task(self.retry_for_process_running())

    async def retry_for_process_running(self) -> None:
        # This method seems to be waiting for some process or attribute.
        pass


class ProcessCreatedDebugModelListener(ABC):
    def __init__(self, observed_created: 'CompletableFuture[Void]'):
        self.observed_created = observed_created

    @abstractmethod
    async def state_changed(self, object: 'TargetObject', state: 'TargetExecutionState') -> None:
        pass


class TargetLauncher:
    # This class seems to be used in various methods but its attributes and methods are not provided.
    pass


class DebuggerTestSpecimen(ABC):
    @abstractmethod
    async def get_launcher_args(self) -> dict:
        pass

    @abstractmethod
    async def run_test_kill(self) -> None:
        pass

    @abstractmethod
    async def run_test_resume_terminates(self) -> None:
        pass


class TargetObject:
    # This class seems to be used in various methods but its attributes and methods are not provided.
    pass


class TargetExecutionState(ABC):
    # This class seems to be used in various methods but its attributes and methods are not provided.
    pass
