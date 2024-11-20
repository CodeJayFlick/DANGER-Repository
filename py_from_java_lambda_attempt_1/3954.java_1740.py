Here is a translation of the provided Java code into equivalent Python:

```Python
import abc
from typing import List

class AbstractHoverProvider(metaclass=abc.ABCMeta):
    def __init__(self, window_name: str) -> None:
        self.window_name = window_name
        self.hover_services = []
        self.enabled = True
        self.program = None
        self.last_field = None
        self.active_hover_service = None

    @property
    def hover_services(self) -> List[object]:
        return self._hover_services

    @hover_services.setter
    def hover_services(self, value: list) -> None:
        if not isinstance(value, list):
            raise TypeError("Hover services must be a list")
        self._hover_services = value

    def add_hover_service(self, service: object) -> None:
        self.hover_services.append(service)
        self.hover_services.sort(key=lambda x: x.get_priority(), reverse=True)

    def remove_hover_service(self, service: object) -> None:
        if service in self.hover_services:
            self.hover_services.remove(service)

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value: object) -> None:
        self._program = value

    def set_program(self, program: object) -> None:
        self.program = program

    def get_program(self) -> object:
        return self.program

    def set_hover_enabled(self, enabled: bool) -> None:
        if self.enabled == enabled:
            return
        self.enabled = enabled
        if self.enabled and not any(service.hover_mode_selected() for service in self.hover_services):
            print("No Popups Enabled")

    @property
    def is_showing(self) -> bool:
        return self.popup_window is not None and self.popup_window.is_shown()

    def close_hover(self) -> None:
        if self.active_hover_service is not None:
            self.active_hover_service = None
            self.last_field = None

        DockingUtils.hide_tip_window()
        if self.popup_window is not None:
            self.popup_window.dispose()
            self.popup_window = None

    @property
    def active_hover_service(self) -> object:
        return self._active_hover_service

    @active_hover_service.setter
    def active_hover_service(self, value: object) -> None:
        if isinstance(value, HoverService):
            self._active_hover_service = value
        else:
            raise TypeError("Active hover service must be a HoverService")

    def scroll(self, amount: int) -> None:
        if self.active_hover_service is not None:
            self.active_hover_service.scroll(amount)

    def dispose(self) -> None:
        Swing.run_later(lambda: self.close_hover())
        self.hover_services.clear()
        self.program = None

    @abc.abstractmethod
    def get_hover_location(self, field_location: object, field: object,
                            field_bounds: tuple, event: object) -> object:
        pass

    def mouse_hovered(self, field_location: object, field: object, 
                      field_bounds: tuple, event: object) -> None:
        if self.is_showing and field == self.last_field:
            return
        if self.program is None:
            return

        component = event.get_component()
        if not component.is_shown():
            # This can happen since we are using a timer.  When the timer fires, 
            # the source component may have been hidden.
            return

        location = self.get_hover_location(field_location, field, field_bounds, event)
        for service in self.hover_services:
            comp = service.get_hover_component(self.program, location, field_location, field)
            if comp is not None:
                self.close_hover()
                self.active_hover_service = service
                self.show_popup(comp, field, event, field_bounds)
                return

    def show_popup(self, comp: object, field: object, 
                   event: object, field_bounds: tuple) -> None:
        self.last_field = field

        kfm = KeyboardFocusManager.get_current_keyboard_focus_manager()
        active_window = kfm.get_active_window()
        if active_window is None:
            active_window = JOptionPane.getRoot_frame()

        popup_window = PopupWindow(active_window, comp)
        popup_window.set_window_name(self.window_name)

        popup_window.add_component_listener(ComponentAdapter())
        popup_window.component_shown.connect(popup_window.show_popup)
        popup_window.component_hidden.connect(popup_window.hide_popup)

    def initialize_listing_hover_handler(self, other_handler: object) -> None:
        if isinstance(other_handler, AbstractHoverProvider):
            other_handler.program = self.program
            other_handler.enabled = self.enabled
            other_handler.hover_services = list(self.hover_services)
```

Please note that Python does not have direct equivalent of Java's abstract classes and interfaces. Instead, you can use ABCMeta from the abc module to create an abstract class in Python.

Also, please note that some parts of this code may need modification based on your specific requirements as it is a translation of Java code into Python.