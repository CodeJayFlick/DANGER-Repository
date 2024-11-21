import tkinter as tk
from typing import List

class WindowUtilities:
    @staticmethod
    def get_title(w) -> str:
        if w is None:
            return None
        
        if isinstance(w, tk.Frame):
            return w.title()
        elif isinstance(w, tk.Toplevel):
            return w.title()
        
        return None
    
    @staticmethod
    def window_for_component(c: object) -> tk.Window:
        if c is None:
            return None
        
        if isinstance(c, tk.Window):
            return c
        
        return c.winfo_toplevel()
    
    @staticmethod
    def get_virtual_screen_bounds() -> tuple[int, int]:
        root = tk.Tk()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        
        return (screen_width, screen_height)
    
    @staticmethod
    def get_visible_screen_bounds() -> tuple[int, int]:
        root = tk.Tk()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        
        return (screen_width, screen_height)
    
    @staticmethod
    def get_screen_bounds(c: object) -> tuple[int, int] | None:
        if c is None or not isinstance(c, tk.Window):
            return None
        
        x = c.winfo_x()
        y = c.winfo_y()
        
        width = c.winfo_width()
        height = c.winfo_height()
        
        return (x + 1, y + 1)  # Add some magic here
    
    @staticmethod
    def center_on_screen(d: tuple[int, int]) -> tuple[int, int]:
        screen_width, screen_height = WindowUtilities.get_virtual_screen_bounds()
        width, height = d
        
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        return (x + 1, y + 1)
    
    @staticmethod
    def center_on_component(parent: object, child: object) -> tuple[int, int]:
        parent_size = parent.winfo_reqwidth(), parent.winfo_reqheight()
        child_size = child.winfo_width(), child.winfo_height()
        
        x = (parent_size[0] - child_size[0]) // 2
        y = (parent_size[1] - child_size[1]) // 2
        
        return (x, y)
    
    @staticmethod
    def ensure_on_screen(c: object) -> None:
        if c is not None and isinstance(c, tk.Window):
            pass
    
    @staticmethod
    def are_modal_dialogs_visible() -> bool:
        root = tk.Tk()
        
        # Add some magic here
        
        return False  # For now, assume no modal dialogs
    
    @staticmethod
    def find_modalest_dialog() -> object | None:
        if not WindowUtilities.are_modal_dialogs_visible():
            return None
        
        # Add some magic here
        
        return None
    
    @staticmethod
    def bring_modalest_dialog_to_front(active_window: tk.Window) -> None:
        root = tk.Tk()
        
        modalest_dialog = find_modalest_dialog()
        
        if modalest_dialog is not None and isinstance(modalest_dialog, tk.Toplevel):
            pass
    
class ScreenBounds:
    def __init__(self, bounds: tuple[int, int], insets: List[tuple[int]]) -> None:
        self.full_bounds = bounds
        self.usable_bounds = (bounds[0] + insets[0][0], bounds[1] + insets[0][1],
                              bounds[2] - sum(inset[0] for inset in insets),
                              bounds[3] - sum(inset[1] for inset in insets))
    
    def get_full_bounds(self) -> tuple[int, int]:
        return self.full_bounds
    
    def get_usable_bounds(self) -> tuple[int, int]:
        return self.usable_bounds
