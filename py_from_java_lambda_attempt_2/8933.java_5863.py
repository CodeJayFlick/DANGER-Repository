Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from threading import Thread
import os

class TagEditorDialog:
    def __init__(self, session):
        self.session = session
        self.list_model = None
        self.list = None
        self.tag_states = set()

        root = tk.Tk()
        root.title("Tag Editor")
        main_panel = tk.Frame(root)
        main_panel.pack(fill="both", expand=True)

        scrollPane = scrolledtext.ScrolledText(main_panel, width=40, height=10)
        list_model = TagStateListModel(self.session.get_match_tags())
        self.list = tk.Listbox(scrollPane, selectmode=tk.MULTIPLE)
        for tag_state in list_model:
            self.list.insert(tk.END, tag_state.tagName)

        scrollPane.pack(side="left", fill="both")
        main_panel.pack(side="top")

        add_button = tk.Button(main_panel, text="Add", command=self.add_tag)
        delete_button = tk.Button(main_panel, text="Delete", command=self.delete_tags)
        edit_button = tk.Button(main_panel, text="Edit", command=self.edit_tag)

        buttons_frame = tk.Frame(main_panel)
        buttons_frame.pack(side="bottom")

        add_button.pack(in_=buttons_frame, side=tk.LEFT)
        delete_button.pack(in_=buttons_frame, side=tk.LEFT)
        edit_button.pack(in_=buttons_frame, side=tk.LEFT)

    def build_work_panel(self):
        return main_panel

    def ok_callback(self):
        self.commit_tag_edits()

    def add_tag(self):
        tag_name = tk.simpledialog.askstring("Input", "Enter tag name:")
        if tag_name is None or "" == str(tag_name).strip():
            return
        new_state = TagState(tag_name, ADD)
        self.list_model.addElement(new_state)

    def delete_tags(self):
        selected_values = list(map(int, self.list.curselection()))
        for state in [self.list_model[i] for i in selected_values]:
            if state.action == UNMODIFIED:
                # mark for deletion, but don't actually delete yet
                state.set_action(DELETE)
            elif state.action == ADD:
                # just remove tags added by the user
                self.list_model.remove_element(state)

    def edit_tag(self):
        pass

class TagStateListModel(list):
    def __init__(self, match_tags):
        super().__init__()
        for tag in match_tags:
            self.append(TagState(tag.name, ADD))

    def addElement(self, state):
        self.append(state)
        self.sort()
        self.fireContentsChanged(0, len(self) - 1)

class TagState:
    UNMODIFIED = "UNMODIFIED"
    ADD = "ADD"
    DELETE = "DELETE"

    def __init__(self, tag_name, action=UNMODIFIED):
        self.tagName = tag_name
        self.action = action

    def get_action(self):
        return self.action

    def set_action(self, action):
        self.action = action

class CommitTagEditsTask:
    def run(self):
        for state in self.tag_states:
            if state.action == ADD:
                # add the tag
                pass
            elif state.action == DELETE:
                # delete the tag
                pass
```

Please note that this is a direct translation of your Java code into Python, and it may not work as expected without further modifications.