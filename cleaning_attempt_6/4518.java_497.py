import tkinter as tk
from tkinter import filedialog

class SelectLanguageDialog:
    def __init__(self, title, approve_button_text):
        self.root = tk.Tk()
        self.root.title(title)
        self.approve_button_text = approve_button_text
        self.language_panel = NewLanguagePanel()

        self.create_widgets()

    def create_widgets(self):
        panel_frame = tk.Frame(self.root)
        panel_frame.pack(fill=tk.BOTH, expand=1)

        language_label = tk.Label(panel_frame, text="Select Language")
        language_label.pack(fill=tk.X)

        self.language_panel.pack(fill=tk.BOTH, expand=1)

        button_frame = tk.Frame(self.root)
        button_frame.pack(fill=tk.X)

        ok_button = tk.Button(button_frame, text=self.approve_button_text, command=lambda: self.ok_callback())
        ok_button.pack(side=tk.LEFT)

        cancel_button = tk.Button(button_frame, text="Cancel", command=lambda: self.cancel_callback())
        cancel_button.pack(side=tk.RIGHT)

    def ok_callback(self):
        if self.check_input():
            self.action_complete = True
            selected_lcs_pair = self.language_panel.get_selected_lcs_pair()
            self.root.destroy()

    def close(self):
        self.root.destroy()
        self.language_panel.dispose()

    def cancel_callback(self):
        self.cancelled = True

    @property
    def was_cancelled(self):
        return self.cancelled

    def check_input(self):
        selected_lcs_pair = self.language_panel.get_selected_lcs_pair()
        if selected_lcs_pair is not None:
            return True
        else:
            return False

    def set_selected_language(self, language):
        tk.after(0, lambda: self.language_panel.set_selected_lcs_pair(language))

    @property
    def selected_language(self):
        self.show_dialog()
        return self.selected_lcs_pair

    def show_dialog(self):
        self.selected_lcs_pair = None
        self.action_complete = False
        # Add code to display the dialog here

if __name__ == "__main__":
    SelectLanguageDialog("Select Language", "OK").root.mainloop()

