import tkinter as tk
from typing import Set, List

class JTreeMouseListenerDelegate:
    def __init__(self, tree: 'tkinter.ttk.Treeview'):
        self.tree = tree
        self.listeners = set()
        self.consumed_pressed = False

        self.install_mouse_listener_delegate()

        self.tree.bind("<ButtonPress-1>", self.mouse_pressed)
        self.tree.bind("<Motion>", self.mouse_moved)

    def install_mouse_listener_delegate(self):
        mouse_listeners = list(self.tree.bindings.keys())
        for listener in mouse_listeners:
            self.tree.unbind(listener)

    def addMouseListener(self, listener: callable) -> None:
        self.listeners.add(listener)

    def removeMouseListener(self, listener: callable) -> None:
        if listener in self.listeners:
            self.listeners.remove(listener)
            self.tree.unbind("<ButtonPress-1>")
            self.tree.bind("<Motion>", self.mouse_moved)

    def mouse_entered(self, event):
        for listener in self.listeners:
            listener(event)

    def mouse_exited(self, event):
        for listener in self.listeners:
            listener(event)

    def mouse_pressed(self, event: 'tkinter.event.Event'):
        if not self.handle_popup_trigger(event):
            return

        if is_potential_drag_selection(event):
            event.x = None
            event.y = None
            self.consumed_pressed = True
            self.tree.focus_set()
        else:
            self.consumed_pressed = False

    def mouse_moved(self, event: 'tkinter.event.Event'):
        handle_popup_trigger(event)

    def mouseClicked(self, event):
        if not self.handle_popup_trigger(event):
            return

        fire_mouse_clicked(event)
        self.consumed_pressed = False

    def mouse_released(self, event):
        if not self.handle_popup_trigger(event):
            maybe_reset_selection_path(event)

    def handle_popup_trigger(self, event: 'tkinter.event.Event'):
        if not event.num == 1:
            return True
        path = self.tree.identify_row(int(event.y))
        if path is None or self.tree.item(path)['values'][0] != '':
            return False

        selection_path = self.tree.getpath(int(path.split(' ')[-1]))
        if not self.tree.selection()[0].get('values')[0] == selection_path[0]:
            set_selected_path_now(selection_path)
            return True
        else:
            return False

    def is_potential_drag_selection(self, event: 'tkinter.event.Event'):
        if event.num != 1 or event.state & (event.modifiers | tk.CONTROL) > 0:
            return False
        path = self.tree.identify_row(int(event.y))
        if path is None or self.tree.item(path)['values'][0] == '':
            return True

    def maybe_reset_selection_path(self, event: 'tkinter.event.Event'):
        if not self.consumed_pressed:
            return
        clicked_path = self.tree.getpath(int(self.tree.identify_row(int(event.y))))
        set_selected_path_now(clicked_path)

    def fire_mouse_clicked(self, event):
        for listener in self.listeners:
            listener(event)
