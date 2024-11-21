import tkinter as tk
from typing import Any, Dict, List

class DockingDialog:
    def __init__(self):
        self.focus_component = None  # allow only one scheduled focus component.
        self.dialog_bounds_map: Dict[str, BoundsInfo] = {}
        self.window_adapter = None
        self.component = None
        self.has_been_focused = False
        self.request_focus_runnable = lambda: None

    def create_hidden_parent_frame(self) -> tk.Toplevel:
        hidden_frame = tk.Toplevel()
        hidden_frame.title("Hidden Frame")
        return hidden_frame

    @classmethod
    def create_dialog(cls, parent: Any, comp: DialogComponentProvider, centered_on_component: Any):
        if isinstance(parent, tk.Toplevel):
            return cls(parent, comp, centered_on_component)
        elif isinstance(parent, tk.Frame):
            return cls(parent, comp, centered_on_component)

        return cls(comp, centered_on_component)

    def __init__(self, parent: Any = None, comp: DialogComponentProvider = None, centered_on_component: Any = None):
        super().__init__()
        self.owning_window_manager = DockingWindowManager.getInstance(parent)
        self.init(comp)
        self.initialize_location_and_size(centered_on_component)

    def initialize_location_and_size(self, centered_on_component: Any):
        key = self.get_key()
        bounds_info = self.dialog_bounds_map.get(key)
        last_bounds = bounds_info.end_bounds
        self.apply_size(last_bounds)  # apply the size before we try to center

        if initial_location := comp.initial_location:
            self.set_location(initial_location)  # NOTE: have to call setLocation() twice because the first time the native peer 
            self.set_location(initial_location)
        elif centered_on_component is not None:
            self.set_centered_on_component(centered_on_component)
        else:
            self.set_centered_on_component(parent)

        bounds_info.start_bounds = Rectangle(self.get_bounds())  # set the default bounds

        if bounds_info.has_been_moved():
            self.apply_location(last_bounds)  # restore the location after the default positioning

    def apply_size(self, saved_bounds: Any):
        remember_size = comp.remember_size
        if remember_size and saved_bounds is not None:
            self.set_size(saved_bounds.width, saved_bounds.height)
            return

        default_size = comp.default_size
        if default_size is not None:
            self.set_size(default_size)

    def apply_location(self, saved_bounds: Any):
        if saved_bounds is None:
            return

        remember_location = comp.remember_location
        if not remember_location:
            return

        self.set_location(saved_bounds.x, saved_bounds.y)

    def get_key(self) -> str:
        scope_object = None
        if comp.use_shared_location:
            scope_object = owning_window_manager
        else:
            scope_object = parent

        return f"{comp.__class__.__name__}{System.identityHashCode(scope_object)}"

    def init(self, provider: DialogComponentProvider):
        self.component = provider
        provider.set_dialog(self)
        contentPane = tk.Frame(self)
        contentPane.pack(fill=tk.BOTH, expand=True)

    def set_centered_on_component(self, c: Any):
        if c is None:
            self.centered_on_screen()
            return

        if not c.winfo_ismapped():
            self.centered_on_screen()

        r = Rectangle(self.get_bounds())
        p = WindowUtilities.center_on_component(c, self)
        r.set_location(p.x, p.y)
        self.set_size(r.width, r.height)

    def close(self):
        self.cleanup()
