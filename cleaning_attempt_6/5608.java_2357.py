from abc import ABCMeta, abstractmethod
import tkinter as tk

class CodeComparisonPanel(metaclass=ABCMeta):
    MINIMUM_PANEL_WIDTH = 50
    
    def __init__(self, owner: str, tool) -> None:
        self.owner = owner
        self.tool = tool
        
    @abstractmethod
    def get_component(self) -> tk.Widget:
        pass

    @abstractmethod
    def get_title(self) -> str:
        pass

    @abstractmethod
    def set_programs(self, left_program: object, right_program: object) -> None:
        pass

    @abstractmethod
    def load_functions(self, left_function: object, right_function: object) -> None:
        pass

    @abstractmethod
    def load_data(self, left_data: object, right_data: object) -> None:
        pass

    @abstractmethod
    def load_addresses(self, left_program: object, right_program: object, 
                       left_addresses: dict, right_addresses: dict) -> None:
        pass

    @abstractmethod
    def dispose(self) -> None:
        pass

    @abstractmethod
    def set_mouse_navigation_enabled(self, enabled: bool) -> None:
        pass

    def get_actions(self) -> list[object]:
        return []

    @property
    def show_titles(self):
        return self._show_titles
    
    @show_titles.setter
    def show_titles(self, value: bool):
        self._show_titles = value

    @abstractmethod
    def get_panel_this_supersedes(self) -> type['CodeComparisonPanel']:
        pass

    @abstractmethod
    def get_action_context(self, component_provider: object, event: tk.Event) -> dict:
        pass

    @abstractmethod
    def program_restored(self, program: object) -> None:
        pass

    @property
    def left_panel_has_focus(self):
        return self._left_panel_has_focus
    
    @left_panel_has_focus.setter
    def left_panel_has_focus(self, value: bool):
        self._left_panel_has_focus = value

    @abstractmethod
    def set_title_prefixes(self, left_title_prefix: str, right_title_prefix: str) -> None:
        pass

    @property
    def left_program(self) -> object:
        return self._programs[0]
    
    @property
    def right_program(self) -> object:
        return self._programs[1]

    @property
    def left_function(self) -> object:
        return self._functions[0]
    
    @property
    def right_function(self) -> object:
        return self._functions[1]

    @property
    def left_data(self) -> object:
        return self._data[0]
    
    @property
    def right_data(self) -> object:
        return self._data[1]

    @abstractmethod
    def get_left_addresses(self) -> dict:
        pass

    @abstractmethod
    def get_right_addresses(self) -> dict:
        pass

    @abstractmethod
    def refresh_left_panel(self) -> None:
        pass
    
    @abstractmethod
    def refresh_right_panel(self) -> None:
        pass

    def update_action_enablement(self) -> None:
        # Do nothing.
        pass

    def set_field_panel_coordinator(self, field_panel_coordinator: object) -> None:
        if self._field_panel_coordinator is not None:
            self._field_panel_coordinator.dispose()
        
        self._field_panel_coordinator = field_panel_coordinator

    @property
    def field_panel_coordinator(self) -> object:
        return self._field_panel_coordinator
    
    def create_field_panel_coordinator(self) -> object:
        # Do nothing.
        pass

    @abstractmethod
    def get_left_field_panel(self) -> tk.Widget:
        pass
    
    @abstractmethod
    def get_right_field_panel(self) -> tk.Widget:
        pass

    @property
    def is_scrolling_synced(self):
        return self._sync_scrolling
    
    @is_scrolling_synced.setter
    def set_scrolling_sync_state(self, value: bool) -> None:
        if self.is_scrolling_synced == value:
            return
        
        self._sync_scrolling = value

        # Refresh the left panel.
        field_panel = self.get_left_field_panel()
        field_panel.update_idletasks()

        # Refresh the right panel.
        field_panel = self.get_right_field_panel()
        field_panel.update_idletasks()

        if not value:
            self.set_field_panel_coordinator(None)
