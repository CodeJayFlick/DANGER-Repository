Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABCMeta, abstractmethod
import typing as t

class AbstractByteViewerPlugin(metaclass=ABCMeta):
    def __init__(self, tool: 'PluginTool'):
        self._current_program = None
        self._are_events_disabled = False
        self._connected_provider = None
        self._disconnected_providers = []

        super().__init__(tool)
        self._connected_provider = self.create_provider(True)

    @abstractmethod
    def create_provider(self, is_connected: bool) -> 'P':
        pass

    def show_connected_provider(self):
        tool.show_component_provider(self.connected_provider, True)

    def create_new_disconnected_provider(self) -> 'P':
        new_provider = self.create_provider(False)
        self._disconnected_providers.append(new_provider)
        tool.show_component_provider(new_provider, True)
        return new_provider

    @abstractmethod
    def init(self):
        pass

    def dispose(self):
        if self.connected_provider is not None:
            self.remove_provider(self.connected_provider)

        for provider in self._disconnected_providers:
            self.remove_provider(provider)

        self._disconnected_providers.clear()

    def write_config_state(self, save_state: 'SaveState'):
        self.connected_provider.write_config_state(save_state)

    @abstractmethod
    def read_config_state(self, save_state: 'SaveState'):
        pass

    def read_data_state(self, save_state: 'SaveState'):
        with self.do_with_events_disabled():
            program_manager_service = tool.get_service('ProgramManager')
            if program_manager_service is not None:
                for provider in [self.connected_provider] + self._disconnected_providers:
                    provider.read_config_state(save_state)
                    provider.read_data_state(save_state)

    def write_data_state(self, save_state: 'SaveState'):
        self.connected_provider.write_data_state(save_state)
        save_state.put_int('Num Disconnected', len(self._disconnected_providers))

        for i, provider in enumerate(self._disconnected_providers):
            state = SaveState()
            program_pathname = provider.get_program().get_domain_file().get_pathname()
            state.put_string('Program Path', program_pathname)
            provider.write_config_state(state)
            provider.write_data_state(state)

    def get_undo_redo_state(self, domain_object: 'DomainObject') -> t.Dict[long, object]:
        state_map = {}

        self.add_undo_redo_state(state_map, domain_object, self.connected_provider)

        for provider in self._disconnected_providers:
            self.add_undo_redo_state(state_map, domain_object, provider)

        if state_map.empty():
            return None
        else:
            return state_map

    def restore_undo_redo_state(self, domain_object: 'DomainObject', state: object):
        state_map = state

        for provider in [self.connected_provider] + self._disconnected_providers:
            self.restore_undo_redo_state(state_map, domain_object, provider)

    @abstractmethod
    def get_transient_state(self) -> t.Any:
        pass

    def restore_transient_state(self, object_state: t.Any):
        with self.do_with_events_disabled():
            state = object_state
            if isinstance(state, tuple):
                save_state = state[0]
                current_selection = state[1]

                self.connected_provider.restore_location(save_state)
                self.connected_provider.set_selection(current_selection)

    def do_with_events_disabled(self, callback: 'Callback'):
        self._are_events_disabled = True

        try:
            callback()
        finally:
            self._are_events_disabled = False

    @abstractmethod
    def events_disabled(self) -> bool:
        pass

    def set_status_message(self, msg: str):
        tool.set_status_info(msg)

    def add_provider(self, provider: 'P'):
        if not isinstance(provider, type):
            raise TypeError(f"Invalid provider {provider}")

        self._disconnected_providers.append(provider)
        provider.set_clipboard_service(tool.get_service('ClipboardService'))

    @abstractmethod
    def update_selection(self, provider: 'ByteViewerComponentProvider', event: 'ProgramSelectionPluginEvent', program: 'Program'):
        pass

    @abstractmethod
    def highlight_changed(self, provider: 'ByteViewerComponentProvider', highlight: 'ProgramSelection'):
        pass

    def close_provider(self, provider: 'ByteViewerComponentProvider'):
        if self.connected_provider == provider:
            tool.show_component_provider(provider, False)
        else:
            self._disconnected_providers.remove(provider)
            self.remove_provider(provider)

    @abstractmethod
    def export_location(self, program: 'Program', location: 'ProgramLocation'):
        pass

    def remove_provider(self, provider: 'ByteViewerComponentProvider'):
        tool.remove_component_provider(provider)
        provider.dispose()

    @abstractmethod
    def update_location(self, program_byte_viewer_component_provider: 'ProgramByteViewerComponentProvider', event: 'ProgramLocationPluginEvent', export: bool):
        pass

    @abstractmethod
    def fire_program_location_plugin_event(self, program_byte_viewer_component_provider: 'ProgramByteViewerComponentProvider', plugin_event: 'ProgramLocationPluginEvent'):
        pass
```

Note that this is a direct translation of the Java code into Python. It's not necessarily idiomatic or optimized for performance in Python.