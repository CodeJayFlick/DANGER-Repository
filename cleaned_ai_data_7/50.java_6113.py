import asyncio

class VisibleAutoReadMemorySpec:
    CONFIG_NAME = "READ_VISIBLE"

    def get_config_name(self):
        return self.CONFIG_NAME

    def get_menu_name(self):
        return AutoReadMemoryAction.NAME_VISIBLE

    def get_menu_icon(self):
        # No direct equivalent in Python, assuming you have a way to load the icon
        pass

    async def read_memory(self, tool: object, coordinates: dict, visible_addresses: set) -> asyncio.Future:
        if not coordinates.get("is_alive_and_reads_present", False):
            return asyncio.create_task(asyncio.sleep(0))

        recorder = coordinates["recorder"]
        accessible_visible = (recorder.get_accessible_process_memory() & visible_addresses)
        memory_manager = coordinates["memory_manager"] = recorder.get_memory_manager()
        already_known = set(memory_manager.get_addresses_with_state(coordinates["snap"], accessible_visible, lambda s: s == TraceMemoryState.KNOWN))

        to_read = accessible_visible - already_known

        if not to_read:
            return asyncio.create_task(asyncio.sleep(0))

        return await recorder.capture_process_memory(to_read, None, False)
