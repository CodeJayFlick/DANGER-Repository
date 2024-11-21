class NoneAutoReadMemorySpec:
    CONFIG_NAME = "READ_NONE"

    def get_config_name(self):
        return self.CONFIG_NAME

    def get_menu_name(self):
        return AutoReadMemoryAction.NAME_NONE

    def get_menu_icon(self):
        # Assuming you have an ICON_NONE variable defined elsewhere
        return ICON_NONE

    async def read_memory(self, tool: 'PluginTool', coordinates: 'DebuggerCoordinates', visible: 'AddressSetView'):
        await AsyncUtils.NIL  # Note that this is a coroutine and should be awaited


class AutoReadMemoryAction:
    NAME_NONE = "None"
    ICON_NONE = None
