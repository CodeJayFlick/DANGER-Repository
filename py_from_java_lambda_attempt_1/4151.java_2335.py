Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class TransactionMonitor(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.busy_icon = None
        self.pref_size = None
        self.program = None
        self.last_tx = None

    def set_program(self, program):
        if self.program is not None:
            self.program.remove_transaction_listener(self)
        if isinstance(program, ProgramDB):
            self.program = program
            self.program.add_transaction_listener(self)
        else:
            self.program = None
        self.last_tx = None
        self.repaint()

    def transaction_started(self, domain_obj, tx):
        self.last_tx = tx
        self.repaint()

    def transaction_ended(self, domain_obj):
        self.last_tx = None
        self.repaint()

    def undo_stack_changed(self, domain_obj):
        # don't care

    def undo_redo_occurred(self, domain_obj):
        # don't care

    def get_preferred_size(self):
        return (self.pref_size[0], self.pref_size[1])

    def paint_component(self, g):
        g.fill_rectangle(0, 0, self.winfo_width(), self.winfo_height())
        if self.last_tx is not None:
            self.busy_icon.place(x=0, y=0)

    def get_tooltip_text(self):
        if self.last_tx is not None:
            list = self.last_tx.get_open_sub_transactions()
            tip = ""
            for item in list:
                if len(tip) != 0:
                    tip += "\n"
                tip += str(item)
            return HTMLUtilities.to_html(str(tip))
        return None

    def repaint(self):
        # call the paint_component method
        self.paint_component(tkinter.Canvas(self))

class ProgramDB:
    pass

class Transaction:
    def get_open_sub_transactions(self):
        pass

def main():
    root = tk.Tk()
    monitor = TransactionMonitor(root)
    program_db = ProgramDB()
    transaction = Transaction()

    # set the program
    monitor.set_program(program_db)

    # start a transaction
    monitor.transaction_started(None, transaction)

    # end the transaction
    monitor.transaction_ended(None)

    root.mainloop()

if __name__ == "__main__":
    main()
```

Please note that this is not exactly equivalent to the Java code. The Python version does not have direct equivalents for some of the Java classes and methods (like `DomainObjectAdapterDB`, `ResourceManager`, etc.). Also, I used tkinter library which is a standard Python GUI library.