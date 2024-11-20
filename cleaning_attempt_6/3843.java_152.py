import tkinter as tk
from tkinter import scrolledtext, filedialog

class CommentDialog:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Set Comment")
        
        # Create panel for dialog
        self.panel = tk.Frame(self.root)
        self.panel.pack(fill="both", expand=True)

        # Create text area and scroll pane
        self.comments_field = scrolledtext.ScrolledText(self.panel, width=50, height=10)
        self.comments_field.set_wrap_length(400)  # Set line wrap

        # Add OK button
        self.ok_button = tk.Button(self.root, text="OK", command=self.apply_callback)
        self.ok_button.pack(fill="x")

        # Add Apply button
        self.apply_button = tk.Button(self.root, text="Apply", command=self.apply_callback)
        self.apply_button.pack(fill="x")

        # Add Cancel button
        self.cancel_button = tk.Button(self.root, text="Cancel", command=self.cancel_callback)
        self.cancel_button.pack(fill="x")

    def show_dialog(self):
        self.comments_field.focus_set()
        self.root.mainloop()

    def apply_callback(self):
        if not hasattr(self, 'orig_comments'):
            return
        orig_comment = self.orig_comments
        new_comment = self.comments_field.get("1.0", "end-1c")
        do_apply(orig_comment)
        self.apply_was_done = True

    def cancel_callback(self):
        self.root.destroy()

class FunctionPlugin:
    pass  # No equivalent in Python, this class is not used here.

def do_apply(comment):
    print(f"Applying comment: {comment}")

# Usage
if __name__ == "__main__":
    dialog = CommentDialog()
    dialog.show_dialog()
