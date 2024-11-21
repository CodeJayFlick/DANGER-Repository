from threading import Timer
import tkinter as tk
from typing import Any, TypeVar

V = TypeVar('V')
E = TypeVar('E')

class PopupRegulator:
    def __init__(self, popup_supplier: 'PopupSource[V, E]'):
        self.popup_source = popup_supplier
        self.popup_timer = None
        self.next_popup_target = None
        self.last_shown_popup_target = None
        self.current_tooltip_info = None

        self.show_popups = True

    def is_popup_showing(self) -> bool:
        return self.popup_window and self.popup_window.wm_state() == 'normal'

    def set_popup_delay(self, delay_ms: int):
        if self.popup_timer:
            self.popup_timer.cancel()
        self.popup_timer = Timer(delay_ms / 1000.0, lambda: self.show_popup_for_mouse_event(None))
        self.popup_timer.start()

    def set_popups_visible(self, visible: bool):
        self.show_popups = visible
        if not self.show_popups:
            self.hide_popup_tooltips()

    def show_popup_for_mouse_event(self, event=None):
        if not self.show_popups or event is None:
            return

        component = event.widget
        tooltip_info = self.popup_source.get_tooltip_info(event)
        tool_tip_component = tooltip_info.tooltip_component
        last_shown_target = self.last_shown_popup_target
        next_target = self.next_popup_target

        if (last_shown_target == next_target and isinstance(tool_tip_component, tk.Toplevel)):
            return

        self.current_tooltip_info = tooltip_info
        self.show_tooltip(tooltip_info)

    def popup_shown(self):
        self.last_shown_popup_target = self.next_popup_target
        self.current_tooltip_info.emphasize()
        self.popup_source.repaint()

    def popup_hidden(self):
        self.current_tooltip_info.de_emphasize()
        self.popup_source.repaint()

    def save_popup_target(self, event=None):
        if not self.show_popups:
            return

        vertex = self.popup_source.get_vertex(event)
        if vertex is None:
            edge = self.popup_source.get_edge(event)
            next_target = edge
        else:
            next_target = vertex

        self.next_popup_target = next_target
        if next_target is None:
            last_shown_target = None
        elif isinstance(next_target, tuple):
            # We've moved off of a target. We will clear that last target so the user can
            # mouse off of a vertex and back on in order to trigger a new popup
            self.last_shown_popup_target = None

    def hide_popup_tooltips(self):
        if self.popup_window:
            self.popup_window.withdraw()

    def show_tooltip(self, tooltip_info: Any) -> None:
        tip_component = tooltip_info.tooltip_component
        event = tooltip_info.mouse_event
        parent_window = self.popup_source.get_popup_parent()
        popup_window = tk.Toplevel(parent_window)
        popup_window.add_component_listener(tk.ComponentAdapter())
        popup_window.show_popup(event)

    def show_popup_window(self, event: Any, component: Any) -> None:
        if not isinstance(component, tk.Widget):
            return

        parent_window = self.popup_source.get_popup_parent()
        popup_window = tk.Toplevel(parent_window)
        popup_window.add_component_listener(tk.ComponentAdapter())
        popup_window.show_popup(event)

    def start(self):
        self.popup_timer.start()

class PopupSource:
    pass
