Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Notebook, Treeview, Combobox, Checkbutton
from tkinter import simpledialog

class CommentsDialog:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Set Comment(s) at Address")
        
        # Create notebook with 5 tabs (EOL, Pre, Post, Plate, Repeatable)
        self.notebook = Notebook(self.root)
        self.eol_tab = ScrolledText(self.notebook)
        self.pre_tab = ScrolledText(self.notebook)
        self.post_tab = ScrolledText(self.notebook)
        self.plate_tab = ScrolledText(self.notebook)
        self.repeatable_tab = ScrolledText(self.notebook)

        # Add tabs to notebook
        self.notebook.add(self.eol_tab, text="EOL Comment")
        self.notebook.add(self.pre_tab, text="Pre Comment")
        self.notebook.add(self.post_tab, text="Post Comment")
        self.notebook.add(self.plate_tab, text="Plate Comment")
        self.notebook.add(self.repeatable_tab, text="Repeatable Comment")

    def showDialog(self):
        # Set title and code unit
        self.root.title("Set Comments at Address " + str(code_unit.getMinAddress()))
        
        # Get comments from code unit
        pre_comment = code_unit.getComment(CodeUnit.PRE_COMMENT)
        post_comment = code_unit.getComment(CodeUnit.POST_COMMENT)
        eol_comment = code_unit.getComment(CodeUnit.EOL_COMMENT)
        plate_comment = code_unit.getComment(CodeUnit.PLATE_COMMENT)
        repeatable_comment = code_unit.getComment(CodeUnit.REPEATABLE_COMMENT)

        # Set comments in text areas
        self.eol_tab.insert('1.0', eol_comment)
        self.pre_tab.insert('1.0', pre_comment)
        self.post_tab.insert('1.0', post_comment)
        self.plate_tab.insert('1.0', plate_comment)
        self.repeatable_tab.insert('1.0', repeatable_comment)

    def setCommentType(self, type):
        # Set selected tab based on comment type
        if type == CodeUnit.EOL_COMMENT:
            self.notebook.select(0)
        elif type == CodeUnit.PRE_COMMENT:
            self.notebook.select(1)
        elif type == CodeUnit.POST_COMMENT:
            self.notebook.select(2)
        elif type == CodeUnit.PLATE_COMMENT:
            self.notebook.select(3)
        elif type == CodeUnit.REPEATABLE_COMMENT:
            self.notebook.select(4)

    def cancelCallback(self):
        if was_changed:
            result = simpledialog.askyesnocancel("Save Changes?", "Some comments were modified. Save Changes?")
            if result == 1: # Yes
                apply_callback()
            elif result == None: # Cancel
                for document, undo_redo_keeper in self.document_undo_redo_map.items():
                    undo_redo_keeper.clear()

    def okCallback(self):
        if was_changed:
            apply_callback()
        self.root.destroy()