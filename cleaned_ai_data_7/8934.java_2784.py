from tkinter import *
import tkinter as tk
from PIL import ImageTk, Image

class TagEditorRenderer:
    def __init__(self):
        self.list = None
        self.list_model = None
        self.panel = None
        self.tag_icon_label = None
        self.undo_button = None
        self.mouse_forwarder = None

    def get_item_text(self, value):
        return value.get_tag_name()

    def get_list_cell_renderer_component(self, jlist, state, index, is_selected, cell_has_focus):
        renderer = super().get_list_cell_renderer_component(jlist, state, index, is_selected, cell_has_focus)
        
        self.initialize_panel(renderer)

        self.tag_icon_label.set_icon(self.get_icon(state))

        if not is_selected:
            state.set_mouse_pressed(False)

        panel.remove(self.undo_button)
        if not state.is_unmodified():
            panel.add(self.undo_button)
            panel.validate()

        self.undo_button.set_tag_state(state)

        return panel

    def get_icon(self, tag_state):
        if tag_state.get_action() == ADD:
            return NEW_TAG_ICON
        elif tag_state.get_action() == DELETE:
            return DELETED_TAG_ICON
        else:
            return EXISTING_TAG_ICON

    def initialize_panel(self, renderer):
        if self.panel is None:
            scrollpane = tk.Scrollbar()
            panel = tk.Frame()
            self.undo_button = RemoveStateButton(state=None)
            self.undo_button.set_background(list.get_background())
            
            # let our color match that of the scroll pane our list is inside of
            panel.set_background(scrollpane.get_background())

            panel.set_layout(tk.BoxLayout(panel, tk.X_AXIS))
            panel.add(self.tag_icon_label)
            panel.add(tk.Frame(width=5))  # create a horizontal strut with width 5
            panel.add(renderer)
            panel.add(tk.Frame(height=tk.TOP, width=tk.TOP))  # make sure we are big enough for our button's height
            panel.add(self.undo_button)

            self.panel = panel

    def set_pressed(self, hovered):
        self.undo_button.set_model().set_armed(hovered)
        self.undo_button.set_model().set_pressed(hovered)


class RemoveStateButton(tk.Button):
    def __init__(self, state=None):
        super().__init__()
        
        if state is not None:
            action = state.get_action()
            if action == ADD:
                set_tooltip_text("Remove this newly added tag")
            else:
                set_tooltip_text("Undo mark for deletion")

            self.set_pressed(state.is_mouse_pressed())

    def get_tag_state(self):
        return self.state

class TagState:
    def __init__(self, name=None, is_unmodified=False, action=ADD):
        self.name = name
        self.is_unmodified = is_unmodified
        self.action = action

    def set_mouse_pressed(self, mouse_pressed):
        pass  # not implemented in Python

    def get_tag_name(self):
        return self.name

    def restore_state(self):
        pass  # not implemented in Python


class GListCellRenderer:
    def __init__(self):
        pass

    def get_item_text(self, value):
        raise NotImplementedError("get_item_text is abstract")

    def get_list_cell_renderer_component(self, jlist, state, index, is_selected, cell_has_focus):
        raise NotImplementedError("get_list_cell_renderer_component is abstract")


class ResourceManager:
    @staticmethod
    def load_image(image_name):
        return ImageTk.PhotoImage(Image.open(image_name))


NEW_TAG_ICON = ResourceManager().load_image('images/tag_blue_add.png')
DELETED_TAG_ICON = ResourceManager().load_image('images/tag_blue_delete.png')
EXISTING_TAG_ICON = ResourceManager().load_image('images/tag_blue.png')
UNDO_ICON = ResourceManager().load_image('images/undo-apply.png')

# usage
renderer = TagEditorRenderer()
