import asyncio

class LldbModelTargetBreakpointSpec:
    def __init__(self):
        self.id = None
        self.enabled = True
        self.count = 0
        self.type = ""
        self.index = ""

    BPT_ACCESS_ATTRIBUTE_NAME = "Access"
    BPT_DISP_ATTRIBUTE_NAME = "Enabled"
    BPT_VALID_ATTRIBUTE_NAME = "Valid"
    BPT_TIMES_ATTRIBUTE_NAME = "Count"
    BPT_TYPE_ATTRIBUTE_NAME = "Type"
    BPT_INDEX_ATTRIBUTE_NAME = "Id"

    async def delete(self):
        await self.model.gate_future(self.manager.delete_breakpoints(self.id))

    async def disable(self):
        self.enabled = False
        await self.model.gate_future(self.manager.disable_breakpoints(self.id))
        return

    async def enable(self):
        self.enabled = True
        await self.model.gate_future(self.manager.enable_breakpoints(self.id))
        return

    def get_id(self):
        return DebugClient.get_id(self.model_object)

    @property
    def kinds(self):
        # This is equivalent to the Java method, but in Python we use properties instead of methods.
        pass  # To be implemented.

    def update_info(self, info, reason):
        pass  # To be implemented.

    def set_enabled(self, enabled, reason):
        self.enabled = enabled

    @property
    def actions(self):
        return []  # This is equivalent to the Java method, but in Python we use properties instead of methods.
        # The actual implementation should create a list and add/remove elements as needed.

    async def add_action(self, action):
        await asyncio.create_task(self.actions.append(action))

    async def remove_action(self, action):
        await asyncio.create_task(self.actions.remove(action))

    async def breakpoint_hit(self):
        target_thread = self.parent_process.get_threads().get_target_thread(self.manager.get_event_thread())
        for action in self.actions:
            await asyncio.create_task(action.breakpoint_hit((self), target_thread, None, self.find_location(target_thread)))

    def find_location(self, object):
        # This is equivalent to the Java method.
        pass  # To be implemented.

class DebugClient:
    @staticmethod
    async def get_id(model_object):
        await asyncio.sleep(0)  # Simulate some work.
        return "id"  # Replace with actual implementation.

# Usage example:

async def main():
    breakpoint_spec = LldbModelTargetBreakpointSpec()
    breakpoint_spec.id = "breakpoint1"
    breakpoint_spec.enabled = True
    breakpoint_spec.count = 5

    await breakpoint_spec.delete()

if __name__ == "__main__":
    asyncio.run(main())
