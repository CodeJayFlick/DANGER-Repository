import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from tkinter import ttk

class TagFilterEditorDialog:
    def __init__(self, controller):
        self.controller = controller
        self.all_tags = {}
        self.excluded_tags = {}

        root = tk.Tk()
        root.title("Tag Chooser")
        root.geometry('300x400')

        frame = tk.Frame(root)
        frame.pack(fill='both', expand=True)

        listbox = tk.Listbox(frame, width=30)
        scrollable_frame = scrolledtext.ScrolledText(frame, height=20, width=40)
        scrollable_frame.grid(row=0, column=1, sticky=tk.NSEW)
        listbox.grid(row=0, column=0, sticky='nsew')

        for tag in self.all_tags:
            if not self.excluded_tags.get(tag):
                listbox.insert(tk.END, f"{tag} (included)")
            else:
                listbox.insert(tk.END, f"{tag} (excluded)")

        def on_listbox_click(event=None):
            selected_index = int(listbox.curselection()[0])
            tag_name = listbox.get(selected_index)
            if " (excluded)" in tag_name:
                self.excluded_tags[tag_name.replace(" (excluded)", "")] = None
            else:
                self.excluded_tags.pop(tag_name, None)

        listbox.bind('<<ListboxSelect>>', on_listbox_click)

        def edit_tag(event=None):
            selected_index = int(listbox.curselection()[0])
            tag_name = listbox.get(selected_index)
            if " (excluded)" in tag_name:
                self.excluded_tags[tag_name.replace(" (excluded)", "")] = None
            else:
                self.excluded_tags.pop(tag_name, None)

        edit_button = tk.Button(frame, text="Manage Tags", command=edit_tag)
        edit_button.grid(row=1, column=0, sticky='nsew')

        root.mainloop()

    def get_excluded_tags(self):
        return {k: v for k, v in self.excluded_tags.items()}

    def rebuild(self):
        pass

class TagInfo:
    def __init__(self, tag_name, is_included):
        self.tag = tag_name
        self.is_included = is_included

    @property
    def get_tag(self):
        return self.tag

    @property
    def is_included(self):
        return self.is_included

    @is_included.setter
    def set_included(self, value):
        self.is_included = value

class TagListModel:
    def __init__(self, all_tags, excluded_tags):
        for tag in all_tags:
            if not excluded_tags.get(tag):
                listbox.insert(tk.END, f"{tag} (included)")
            else:
                listbox.insert(tk.END, f"{tag} (excluded)")

if __name__ == "__main__":
    controller = None
    dialog = TagFilterEditorDialog(controller)
