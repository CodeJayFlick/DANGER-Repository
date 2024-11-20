import tkinter as tk
from PIL import ImageTk, Image

class FunctionTagButtonPanel:
    def __init__(self, source_panel, target_panel):
        self.source_panel = source_panel
        self.target_panel = target_panel
        self.create_button_panel()

    def create_button_panel(self):
        panel = tk.Frame()
        panel.pack(fill="both", expand=True)

        add_img = ImageTk.PhotoImage(Image.open("images/2rightarrow.png"))
        remove_img = ImageTk.PhotoImage(Image.open("images/2leftarrow.png"))

        self.add_btn = tk.Button(panel, text="", image=add_img)
        self.remove_btn = tk.Button(panel, text="", image=remove_img)
        self.delete_btn = tk.Button(panel, text="Deletes the selected tags from the program")

        self.add_btn.pack(side=tk.LEFT)
        self.remove_btn.pack(side=tk.LEFT)
        self.delete_btn.pack(side=tk.LEFT)

    def source_panel_selection_changed(self, valid_function):
        has_selection = self.source_panel.has_selection()
        is_immutable = self.source_panel.is_selection_immutable()

        if not has_selection:
            self.source_panel.clear_selection()

        self.add_btn.config(state="normal" if (has_selection and valid_function) else "disabled")
        self.remove_btn.config(state="disabled")

    def target_panel_selection_changed(self, valid_function):
        has_selection = self.target_panel.has_selection()
        is_immutable = self.target_panel.is_selection_immutable()

        if not has_selection:
            self.target_panel.clear_selection()

        self.add_btn.config(state="disabled")
        self.remove_btn.config(state="normal" if (has_selection and valid_function) else "disabled")

    def delete_tags(self):
        # This method is called when the 'Delete' button is clicked
        pass

# Example usage:
source_panel = SourceTagsPanel()
target_panel = TargetTagsPanel()

panel = FunctionTagButtonPanel(source_panel, target_panel)
