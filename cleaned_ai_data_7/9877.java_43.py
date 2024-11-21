import tkinter as tk


class HintTextArea:
    def __init__(self, hint):
        self.hint = hint
        self.text_area = tk.Text()
        self.text_area.pack()

    def set_text(self, text):
        if not text.strip():
            self.show_hint()
        else:
            self.remove_hint()
            self.text_area.delete(1.0, 'end')
            self.text_area.insert('1.0', text)

    def show_hint(self):
        hint = f"<i>{self.hint}</i>"
        self.text_area.config(state='normal')
        self.text_area.tag_config('hint', font=('Helvetica', 12), foreground='#888888')
        self.text_area.insert('1.0', hint, 'hint')
        self.text_area.config(state='disabled')

    def remove_hint(self):
        self.text_area.delete(1.0, tk.END)


root = tk.Tk()
text_area = HintTextArea("Hint Text")
root.mainloop()
