Here is the translation of the given Java code into equivalent Python:

```Python
import asyncio
from ghidra_dbg_target import *
from ghidra_dbg_test import *

class AbstractModelForGdbThreadActivationTest:
    def __init__(self):
        self.THREAD_PATTERN = PathPattern.parse("Inferiors[].Threads[]")

    async def get_specimen(self):
        return GdbLinuxSpecimen.PRINT

    async def get_activatable_things(self) -> set[TargetObject]:
        inf1 = await m.get_added_waiter().wait(PathUtils.parse("Inferiors[1].Threads[1]"))
        inf2 = await m.get_added_waiter().wait(PathUtils.parse("Inferiors[2].Threads[2]"))

        specimen = await self.get_specimen()
        launcher = find_launcher()  # root launcher should generate new inferiors
        await wait_on(launcher.launch(await specimen.get_launcher_args()))
        await wait_on(launcher.launch(await specimen.get_launcher_args()))

        await asyncio.wait_for(m.get_model(), timeout=200)

        return {await wait_on(inf1), await wait_on(inf2)}

    async def get_expected_default_active_path(self) -> list[str]:
        return PathUtils.parse("Inferiors[2].Threads[2].Stack[0]")

    async def activate_via_interpreter(self, obj: TargetObject, interpreter: TargetInterpreter):
        index = Unique.assert_one(set(THREAD_PATTERN.match_indices(obj.path)))
        await wait_on(interpreter.execute(f"thread {index}.1"))

    async def assert_active_via_interpreter(self, expected: TargetObject, interpreter: TargetInterpreter):
        output = await wait_on(interpreter.capture_execute("info threads -gid"))
        line = next((l for l in (output.split("\n")) if l.strip().startswith("*")), None)
        thread_gid = line.split()[2]
        assert expected.path == THREAD_PATTERN.apply_indices(thread_gid, thread_gid).get_singleton_path()
```

Note that this translation is not a direct conversion from Java to Python. The code has been modified to be more idiomatic in Python and takes advantage of its asynchronous capabilities using the `asyncio` library.