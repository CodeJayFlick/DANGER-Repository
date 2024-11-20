Here is a translation of the Java code into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's `CompletableFuture` and some other classes. So, I used the built-in `asyncio.futures.Future()` to simulate a similar behavior.

Also, Python is dynamically typed language so there is no need for explicit type declarations like in Java.