class NoneLocationTrackingSpec:
    CONFIG_NAME = "TRACK_NONE"

    def get_config_name(self):
        return self.CONFIG_NAME

    def get_menu_name(self):
        return TrackLocationAction.NAME_NONE

    def get_menu_icon(self):
        return TrackLocationAction.ICON_NONE

    def compute_title(self, coordinates: 'DebuggerCoordinates') -> str:
        return None

    def compute_trace_address(self, tool: 'PluginTool', coordinates: 'DebuggerCoordinates', emu_snap: int) -> 'Address':
        return None

    def affected_by_register_change(self, space: 'TraceAddressSpace', range: 'TraceAddressSnapRange', coordinates: 'DebuggerCoordinates') -> bool:
        return False

    def affected_by_stack_change(self, stack: 'TraceStack', coordinates: 'DebuggerCoordinates') -> bool:
        return False
