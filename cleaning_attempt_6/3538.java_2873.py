import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime

class CommentHistoryPanel:
    NO_HISTORY = "No History Found"

    def __init__(self):
        self.root = tk.Tk()
        self.text_area = scrolledtext.ScrolledText(self.root, width=80, height=20)
        self.text_area.pack()

    def show_comment_history(self, program, addr):
        self.text_area.delete(1.0, "end")
        
        history_items = program.get_listing().get_comment_history(addr, 0) # commentType is not used in this function
        if len(history_items) == 0:
            self.text_area.insert("1.0", self.NO_HISTORY)
            return

        for item in history_items:
            self.format_history(item)

    def format_history(self, history):
        offset = int(self.text_area.index("end"))
        
        user_name = history.get_user_name()
        if offset > 0:
            user_name = "\n" + user_name
        self.text_area.insert(f"{offset}\n", f"[{user_name}]\n")

        date = datetime.fromtimestamp(history.get_modification_date()).strftime("%Y-%m-%d %H:%M:%S")
        self.text_area.insert(f"{offset}\n", f"\t{date}\n")
        
        offset += 1
        for line in history.get_comments().split("\n"):
            if len(line) > 0:
                self.text_area.insert(f"{offset}\n", f"[{line}]\n")
                offset += 1

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    panel = CommentHistoryPanel()
    # call show_comment_history function with your program and address
    panel.show_comment_history(None, None)  # replace None with actual values
    panel.run()
