from tkinter import *
import collections

class AbstractDebuggerMapProposalDialog:
    def __init__(self, title):
        self.root = Tk()
        self.root.title(title)
        self.create_widgets()

    def create_widgets(self):
        panel = Frame(self.root)

        table_model = self.create_table_model()
        table = Listbox(panel, listvariable=table_model)
        table.pack(side=LEFT)

        filter_panel = Frame(panel)
        Label(filter_panel, text="Filter:").pack(side=LEFT)
        entry = Entry(filter_panel)
        entry.pack(side=LEFT)
        panel.add(filter_panel, side=BOTTOM)

        self.root.add(panel)

    def create_table_model(self):
        # Implement this method to return a table model
        pass

    def remove_entry(self, entry):
        # Remove the given entry from the table model
        pass

    def ok_callback(self):
        adjusted = self.table_model.get()
        self.close()

    def cancel_callback(self):
        adjusted = None
        self.close()

    def get_adjusted(self):
        return self.adjusted

    def adjust_collection(self, tool, collection):
        self.table_model.clear()
        self.table_model.extend(collection)
        tool.show_dialog(self.root)
        return self.get_adjusted()

# Usage example:
dialog = AbstractDebuggerMapProposalDialog("Title")
