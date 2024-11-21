Here is the equivalent Python code:

```Python
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
```

Please note that Python does not have direct equivalent of Java's `CompletableFuture` or `Icon`. I've replaced them with Python's built-in support for asynchronous programming (`async def`) and a placeholder variable `ICON_NONE`, which you would need to define elsewhere in your code.