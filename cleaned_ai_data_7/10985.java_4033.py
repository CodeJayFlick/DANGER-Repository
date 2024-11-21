import tkinter as tk
from typing import Dict, Set

class FileOpenDropHandler:
    def __init__(self, tool: object, component: tk.Widget) -> None:
        self.tool = tool
        self.component = component
        self.handlers: Dict[tk.Misc.DataFlavor, 'FileOpenDataFlavorHandler'] = {}
        self.drop_target_adapter: object = None
        self.global_drop_target: object = None

    def dispose(self) -> None:
        # todo implement dispose method in Python equivalent of Java's dispose()
        pass

    def is_drop_ok(self, e: tk.DragEvent) -> bool:
        for data_flavor in self.handlers.keys():
            if e.data_type == data_flavor.mime_type:
                return True
        return False

    def add(self, obj: object, e: tk.DropEvent, f: tk.Misc.DataFlavor) -> None:
        handler = self.handlers.get(f)
        if handler is not None:
            handler.handle(obj, e)

    def drag_under_feedback(self, ok: bool, e: tk.DragEvent) -> None:
        # todo implement drag under feedback in Python equivalent of Java's dragUnderFeedback()
        pass

    def undo_drag_under_feedback(self) -> None:
        # todo implement undo drag under feedback in Python equivalent of Java's undoDragUnderFeedback()
        pass

    def initialize_components(self, comp: tk.Widget) -> None:
        if isinstance(comp, tk.CellRendererPane):
            return
        elif hasattr(comp, 'winfo_children'):
            for child in comp.winfo_children():
                self.initialize_components(child)

    def deinitialize_components(self, comp: tk.Widget) -> None:
        if isinstance(comp, tk.CellRendererPane):
            return
        elif hasattr(comp, 'winfo_children'):
            for child in comp.winfo_children():
                self.deinitialize_components(child)
        else:
            dt = comp.cget('drop_target')
            if isinstance(dt, CascadedDropTarget):
                new_dt = dt.remove_drop_target(self.global_drop_target)
                comp.config(drop_target=new_dt)

    def component_added(self, e: tk.ContainerEvent) -> None:
        self.initialize_components(e.widget)

    def component_removed(self, e: tk.ContainerEvent) -> None:
        self.deinitialize_components(e.widget)

@staticmethod
def add_data_flavor_handler(data_flavor: tk.Misc.DataFlavor, handler: 'FileOpenDataFlavorHandler') -> None:
    FileOpenDropHandler.handlers[data_flavor] = handler

@staticmethod
def remove_data_flavor_handler(data_flavor: tk.Misc.DataFlavor) -> object:
    return FileOpenDropHandler.handlers.pop(data_flavor)
