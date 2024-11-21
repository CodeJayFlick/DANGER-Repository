import tkinter as tk
from PIL import Image, ImageTk


class TreeDragSrcAdapter:
    MOVE_ CURSOR_FILENAME = "images/dragMoveCursor.gif"
    COPY_CURSOR_FILENAME = "images/dragCopyCursor.gif"

    def __init__(self):
        self.feedback_cursor = None
        self.copy_cursor = None
        self.move_cursor = None

    def get_drop_ok_cursor(self, action):
        if self.feedback_cursor is not None:
            return self.feedback_cursor
        else:
            return super().get_drop_ok_cursor(action)

    def get_cursor(self, action, relative_mouse_pos):
        c = None
        if (action & 0x1):  # ACTION_ LINK
            return super().get_drop_ok_cursor(action)
        elif (action & 0x2):  # ACTION_MOVE
            c = DragSource.DefaultMoveDrop
            if relative_mouse_pos != 0:
                c = self.get_move_cursor()
        else:  # ACTION_COPY
            c = DragSource.DefaultCopyDrop
            if relative_mouse_pos != 0:
                c = self.get_copy_cursor()
        return c

    def set_feedback_cursor(self, cursor):
        self.feedback_cursor = cursor

    def get_move_cursor(self):
        if not hasattr(self, 'move_cursor') or self.move_cursor is None:
            image = Image.open(self.MOVE_CURSOR_FILENAME)
            hot_spot = (0, 16)
            self.move_cursor = tk.PhotoImage(image=image, master=tk.Tk())
        return self.move_cursor

    def get_copy_cursor(self):
        if not hasattr(self, 'copy_cursor') or self.copy_cursor is None:
            image = Image.open(self.COPY_CURSOR_FILENAME)
            hot_spot = (0, 24)
            self.copy_cursor = tk.PhotoImage(image=image, master=tk.Tk())
        return self.copy_cursor

    @staticmethod
    def create_cursor(filename, cursor_name, hot_spot):
        icon = ResourceManager.load_image(filename)
        image = Image.open(icon.filename)
        toolkit = tk.get_default_toolkit()
        cursor = toolkit.create_custom_cursor(image=ImageTk.PhotoImage(image), hotspot=hot_spot, name=cursor_name)
        return cursor
