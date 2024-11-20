import asyncio
from typing import Collection, List

class DebuggerProgramLaunchOpinion:
    def get_offers(self, program: str, tool: str, service: dict) -> Collection[dict]:
        model_factories = list(service.values())
        assert len(model_factories) == 1
        factory = model_factories[0]
        assert isinstance(factory, TestDebuggerModelFactory)

        return [TestDebuggerProgramLaunchOffer()]

class DebuggerProgramLaunchOffer:
    def launch_program(self, monitor: str, prompt: bool) -> asyncio.Future:
        return asyncio.futures.Future()

    def get_config_name(self) -> str:
        return "TEST"

    def get_menu_parent_title(self) -> str:
        return "Debug it"

    def get_menu_title(self) -> str:
        return "in Fake Debugger"


class TestDebuggerModelFactory:
    pass


TestDebuggerProgramLaunchOpinion = DebuggerProgramLaunchOpinion()
