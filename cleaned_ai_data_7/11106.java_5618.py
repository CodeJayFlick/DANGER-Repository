import tkinter as tk
from tkinter import filedialog, messagebox
from threading import Thread

class FileViewer:
    def __init__(self):
        self.root = tk.Tk()
        self.reader = None
        self.model = None
        self.event_listener = None
        self.viewport_utility = None
        self.table = None
        self.scrollpane = None
        self.slider = None
        self.toolbar = None

    def set_up(self, reader, model, event_listener):
        self.reader = reader
        self.model = model
        self.event_listener = event_listener
        
        # Use a border layout so the table will take up all available space.
        self.root.geometry("800x600")
        self.root.title("File Viewer")

    def update(self, o, arg):
        if isinstance(o, FVEventListener) and isinstance(arg, FVEvent):
            if tkinter._thread_initiated:
                self.handle_fv_event(arg)
            else:
                self.root.after(0, lambda: self.handle_fv_event(arg))

    def handle_fv_event(self, event):
        switch (event.event_type):
            case COPY_SELECTION:
                try:
                    byte_arrays = reader.read_bytes(model.selected_byte_start, model.selected_byte_end)

                    # Create strings from the byte arrays.
                    str_builder = StringBuilder()
                    for byteArray in byte_arrays:
                        str = new String(byteArray)
                        str_builder.append(str)

                    string_selection = StringSelection(str_builder.toString())

                    # Copy it to the clipboard.
                    clipboard.set_contents(string_selection, None)
                except IOException as e:
                    messagebox.showerror("Error", "Error reading bytes from file")

            case DECREMENT_SELECTION:
                if table.get_selected_row() >= 0:
                    table.decrement_selection(int(event.arg))
                    slider.sync_with_viewport()
                    table.restore_selection()

            # ... and so on for the rest of the cases.

    def set_scroll_lock(self, lock):
        self.toolbar.scroll_lock_btn.set(selected=lock)

    def view_end_of_file(self, update_slider=True):
        try:
            table.clear()
            model.clear()
            ((FVTableModel) (table.model)).add_rows_to_bottom(reader.read_last_chunk())
            viewport_utility.move_viewport_to_bottom()
            table.restore_selection()

            if update_slider:
                slider.set_value(slider.get_maximum())

        except IOException as e:
            messagebox.showerror("Error", "Error reading last chunk of data")

    def view_top_of_file(self):
        try:
            table.clear()
            model.clear()
            ((FVTableModel) (table.model)).add_rows_to_bottom(reader.read_next_chunk())
            viewport_utility.move_viewport_to_top()
            table.restore_selection()

        except IOException as e:
            messagebox.showerror("Error", "Error reading first chunk of data")

    def update_view_to_file_pos(self, file_pos):
        model.clear()
        table.clear()
        try:
            lines = reader.read_next_chunk_from(file_pos)

            # If the number of lines read is < 1, then we're at the end of the file. If we
            # try to read a chunk from here we'll get nothing in return and will have nothing
            # to display. So back up from the end until we get a full line that we can show.
            i = 0
            while len(lines) < 1:
                lines = reader.read_next_chunk_from(file_pos - i)
                i += 1

            ((FVTableModel) table.model).add_rows_to_top(lines)
            viewport_utility.move_viewport_to_top()

        except IOException as e:
            messagebox.showerror("Error", "Error reading next chunk of data")

    def reload_file(self):
        try:
            reader.reload()
            slider.set_maximum(reader.get_file_size())

        except IOException as e:
            messagebox.showerror("Error", "Error reading file size")

        if not self.toolbar.scroll_lock_btn.selected():
            fv_event = FVEvent(EventType.SCROLL_END, True)
            event_listener.send(fv_event)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    reader = Reader()
    model = Model()
    event_listener = EventListener()
    viewport_utility = ViewportUtility(event_listener)
    table = Table(reader, viewport_utilty, model, event_listener)
    scrollpane = JScrollPane(table)
    slider = Slider(scrollpane, table, viewport_utility, model, reader, event_listener)
    toolbar = Toolbar(event_listener)

    viewer = FileViewer()
    viewer.set_up(reader, model, event_listener)
    viewer.run()

class FVEvent:
    def __init__(self, event_type):
        self.event_type = event_type

class EventListener:
    def send(self, fv_event):
        pass
