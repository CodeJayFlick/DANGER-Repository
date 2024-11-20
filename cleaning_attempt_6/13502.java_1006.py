import unittest
from tkinter import filedialog
from tkinter import messagebox
from tkinter import Tk
from tkinter import ttk
from os.path import join, getsize
from tempfile import TemporaryDirectory

class PathManagerTest(unittest.TestCase):

    def setUp(self):
        self.root = Tk()
        self.root.withdraw()

    def tearDown(self):
        pass

    def test_up_arrow(self):
        paths = [Path(join('c:\\', 'path_{}'.format(i))) for i in range(1, 5)]
        path_manager = PathManager(paths)
        table = ttk.Treeview(self.root)
        frame = self.root
        frame.title("Test")
        frame.geometry("300x200")

        run_swing(lambda: {
            path_manager.set_component(table)
            frame.add(path_manager.get_component())
            frame.pack()
        })

        select_row(3)

        up_button = find_button_by_icon(self, "images/up.png", self.root)
        assert up_button is not None
        press_button(up_button, True)

        row = table.selection()[0]
        self.assertEqual(row, 2)
        self.assertEqual(table.item(row)['values'][1], 'c:\\path_4')

    def test_down_arrow(self):
        paths = [Path(join('c:\\', 'path_{}'.format(i))) for i in range(1, 5)]
        path_manager = PathManager(paths)
        table = ttk.Treeview(self.root)
        frame = self.root
        frame.title("Test")
        frame.geometry("300x200")

        run_swing(lambda: {
            path_manager.set_component(table)
            frame.add(path_manager.get_component())
            frame.pack()
        })

        select_row(2)

        down_button = find_button_by_icon(self, "images/down.png", self.root)
        assert down_button is not None
        press_button(down_button, True)

        row = table.selection()[0]
        self.assertEqual(row, 3)
        self.assertEqual(table.item(row)['values'][1], 'c:\\path_3')

    def test_remove(self):
        paths = [Path(join('c:\\', 'path_{}'.format(i))) for i in range(1, 5)]
        path_manager = PathManager(paths)
        table = ttk.Treeview(self.root)
        frame = self.root
        frame.title("Test")
        frame.geometry("300x200")

        run_swing(lambda: {
            path_manager.set_component(table)
            frame.add(path_manager.get_component())
            frame.pack()
        })

        select_row(3)

        button = find_button_by_icon(self, "images/edit-delete.png", self.root)
        assert button is not None
        press_button(button, True)

    def test_add_button(self):
        temp_dir = TemporaryDirectory()

        path_manager = PathManager([])
        table = ttk.Treeview(self.root)
        frame = self.root
        frame.title("Test")
        frame.geometry("300x200")

        run_swing(lambda: {
            path_manager.set_component(table)
            frame.add(path_manager.get_component())
            frame.pack()
        })

        Preferences.setProperty('LAST_IMPORT_DIRECTORY', temp_dir.name)

        button = find_button_by_icon(self, "images/Plus.png", self.root)
        assert button is not None
        press_button(button, False)

    def test_cancel_add(self):
        temp_dir = TemporaryDirectory()

        path_manager = PathManager([])
        table = ttk.Treeview(self.root)
        frame = self.root
        frame.title("Test")
        frame.geometry("300x200")

        run_swing(lambda: {
            path_manager.set_component(table)
            frame.add(path_manager.get_component())
            frame.pack()
        })

        Preferences.setProperty('LAST_IMPORT_DIRECTORY', temp_dir.name)

        button = find_button_by_icon(self, "images/Plus.png", self.root)
        assert button is not None
        press_button(button, False)

    def test_clear(self):
        run_swing(lambda: {
            path_manager.clear()
        })
        self.assertEqual(0, table.get_children())

    def select_row(self, row):
        run_swing(lambda: {
            table.selection_set(row)
        })

    def find_button_by_icon(self, icon_path, root):
        for widget in root.winfo_children():
            if isinstance(widget, ttk.Button) and widget.cget('image') == icon_path:
                return widget
        return None

    def press_button(self, button, wait=False):
        run_swing(lambda: {
            messagebox.showinfo("Button Pressed", "You pressed the button")
        })

if __name__ == '__main__':
    unittest.main()
