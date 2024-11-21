import tkinter as tk
from PIL import Image, ImageDraw


class MemoryMapPluginScreenShots:
    def __init__(self):
        pass

    @staticmethod
    def test_memory_map():
        perform_action("Memory Map", "DockingWindows", True)

        provider = get_provider("Memory Map")
        move_provider_to_its_own_window(provider)
        component = get_dockable_component(provider)

        capture_isolated_component(component, 800, 225)


    @staticmethod
    def test_add_memory_block():
        perform_action("Add Block", "MemoryMapPlugin", False)

        dialog = get_dialog()
        combo_box = instance_field(dialog, "comboBox")
        select_item(combo_box, "Byte Mapped")

        capture_dialog()

        draw_rectangle_around(combo_box, (0, 255, 0), 10)


    @staticmethod
    def test_move_memory():
        perform_action("Memory Map", "DockingWindows", True)

        provider = get_provider("Memory Map")
        component = provider.get_component()
        table = find_component(component, GhidraTable)
        wait_for_swing()

        select_row(table, ".text")

        action = instance_field(provider, "moveAction")
        perform_action(action, False)

        capture_dialog()


    @staticmethod
    def test_split_memory_block():
        perform_action("Memory Map", "DockingWindows", True)

        provider = get_provider("Memory Map")
        component = provider.get_component()
        table = find_component(component, GhidraTable)
        wait_for_swing()

        select_row(table, ".text")

        action = instance_field(provider, "splitAction")
        perform_action(action, False)

        capture_dialog()


    @staticmethod
    def test_memory_expand_up():
        perform_action("Memory Map", "DockingWindows", True)

        provider = get_provider("Memory Map")
        component = provider.get_component()
        table = find_component(component, GhidraTable)
        wait_for_swing()

        select_row(table, ".text")

        action = instance_field(provider, "expandUpAction")
        perform_action(action, False)

        capture_dialog()


    @staticmethod
    def test_memory_expand_down():
        perform_action("Memory Map", "DockingWindows", True)

        provider = get_provider("Memory Map")
        component = provider.get_component()
        table = find_component(component, GhidraTable)
        wait_for_swing()

        select_row(table, ".text")

        action = instance_field(provider, "expandDownAction")
        perform_action(action, False)

        capture_dialog()


    @staticmethod
    def test_set_image_base_dialog():
        perform_action("Memory Map", "DockingWindows", True)

        provider = get_provider("Memory Map")
        component = provider.get_component()
        table = find_component(component, GhidraTable)
        wait_for_swing()

        select_row(table, ".text")

        action = instance_field(provider, "setBaseAction")
        perform_action(action, False)

        capture_dialog()


    @staticmethod
    def draw_text(text: str, color: tuple, point: tuple, size: int):
        image = Image.new('RGB', (450, 175), (255, 255, 255))
        draw = ImageDraw.Draw(image)
        draw.text((point[0], point[1]), text, font=('Arial', size), fill=color)


    @staticmethod
    def select_row(table: tk.Frame, text: str):
        model = table.model()
        column_count = model.columnCount()
        row_index = -1

        for i in range(column_count):
            if model.headerData(i)[0] == "Name":
                break

        for i in range(model.rowCount()):
            value_at_i = model.valueAt(i, 0)
            if str(value_at_i) == text:
                row_index = i
                break

        table.selection_set(row_index)


    @staticmethod
    def select_item(combo_box: tk.Frame, text: str):
        item_count = combo_box.size()
        for i in range(item_count):
            value_at_i = combo_box.get(i)
            if str(value_at_i) == text:
                return

        raise Exception("Item not found")


def perform_action(action_name: str, window_title: str, is_modal: bool):
    pass


def get_provider(provider_name: str):
    pass


def move_provider_to_its_own_window(provider: tk.Frame):
    pass


def get_dockable_component(component: tk.Frame):
    pass


def capture_isolated_component(component: tk.Frame, width: int, height: int):
    pass


def draw_rectangle_around(combo_box: tk.Frame, color: tuple, size: int):
    pass


def wait_for_swing():
    pass
