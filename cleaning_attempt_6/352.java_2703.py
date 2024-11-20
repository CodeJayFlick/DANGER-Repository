import asyncio
from typing import List

class DebuggerTargetsPluginScreenShots:
    def __init__(self):
        self.model_service = None  # type: DebuggerModelServiceInternal
        self.targets_plugin = None  # type: DebuggerTargetsPlugin
        self.targets_provider = None  # type: DebuggerTargetsProvider

    async def setUp(self):
        await asyncio.create_task(self.add_plugins())

    async def add_plugins(self):
        if not hasattr(self, 'model_service'):
            self.model_service = await self._add_plugin(DebuggerModelServiceProxyPlugin)
        if not hasattr(self, 'targets_plugin'):
            self.targets_plugin = await self._add_plugin(DebuggerTargetsPlugin)
        if not hasattr(self, 'targets_provider'):
            self.targets_provider = await self._wait_for_component_provider(DebuggerTargetsProvider)

    async def test_capture_debugger_targets_plugin(self):
        model_service = self.model_service
        model_service.add_model(ScreenShotDebuggerObjectModel("DEMO@1234abcd localhost:12345"))
        model_service.add_model(ScreenShotDebuggerObjectModel("DEMO@4321fedc debug-demo:12345"))

        await asyncio.create_task(self.capture_isolated_provider(self.targets_provider, 400, 300))

    async def test_capture_debugger_connect_dialog(self):
        model_service = self.model_service
        model_service.set_model_factories([ScreenShotDebuggerModelFactory()])
        await asyncio.create_task(self.perform_action(self.targets_provider.actionConnect, False))
        await asyncio.create_task(self.capture_dialog(DebuggerConnectDialog))

class ScreenShotDebuggerObjectModel:
    def __init__(self, display):
        self.display = display
        self.root = DefaultTargetModelRoot(self, "Session")

    def get_brief(self):
        return self.display

    async def fetch_model_root(self):
        return asyncio.create_task(CompletableFuture.completedFuture(self.root))

    def get_address_factory(self):
        raise AssertionError()

class ScreenShotDebuggerModelFactory:
    @property
    def remote_option(self) -> Property[bool]:
        return Property.from_accessors(bool, lambda: True)

    @property
    def host_option(self) -> Property[str]:
        return Property.from_accessors(str, lambda: "localhost")

    @property
    def port_option(self) -> Property[int]:
        return Property.from_accessors(int, lambda: 12345)

    async def build(self):
        raise AssertionError()

class DefaultTargetModelRoot:
    def __init__(self, parent, display):
        self.parent = parent
        self.display = display

    def add_model_root(self, root):
        pass

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    plugin = DebuggerTargetsPluginScreenShots()
    loop.run_until_complete(plugin.setUp())
