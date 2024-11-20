import asyncio
from ghidra_dbg_target import *
from ghidra_dbg_test import *

class AbstractModelForGdbFrameActivationTest:
    STACK_PATTERN = PathPattern.parse("Inferiors[1].Threads[1].Stack[]")

    def get_specimen(self):
        return GdbLinuxSpecimen.STACK

    async def activate_via_interpreter(self, obj: TargetObject, interpreter: TargetInterpreter) -> None:
        index = next((i for i in self.STACK_PATTERN.match_indices(obj.path)), None)
        await asyncio.create_task(interpreter.execute(f"frame {index}"))

    async def assert_active_via_interpreter(self, expected: TargetObject, interpreter: TargetInterpreter) -> None:
        line = (await asyncio.create_task(interpreter.execute_capture("frame"))).strip()
        self.assertFalse(line.startswith("\n"))
        self.assertTrue(line.startswith("#"))
        frame_level = line[1:].split()[0]
        self.assertEqual(expected.path, self.STACK_PATTERN.apply_indices(frame_level).get_singleton_path())

    async def get_activatable_things(self) -> set:
        await asyncio.create_task(m.get_added_waiter().wait(PathPattern.parse("Inferiors[1].Threads[1].Stack[0]")))
        await asyncio.create_task(m.get_added_waiter().wait(PathPattern.parse("Inferiors[1].Threads[1].Stack[1]")))
        await asyncio.create_task(m.get_added_waiter().wait(PathPattern.parse("Inferiors[1].Threads[1].Stack[2]")))

        specimen = self.get_specimen()
        launcher = find_launcher()  # root launcher should generate new inferiors
        await asyncio.create_task(wait_on(launcher.launch(specimen.get_launcher_args())))
        breakpoints = find_breakpoint_spec_container(list())
        await asyncio.create_task(breakpoints.place_breakpoint("break_here", set([TargetBreakpointKind.SW_EXECUTE])))
        inf = (await asyncio.create_task(m.get_added_waiter().wait(PathPattern.parse("Inferiors[1]")))).get()
        await asyncio.create_task(inf.resume())

        await asyncio.create_task(wait_settled(m.get_model(), 200))

        return {obj async for obj in [frame0, frame1, frame2]}
