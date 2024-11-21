Here is a translation of the Java code into equivalent Python:

```Python
from tkinter import Tk, Toplevel, Label, Button, Listbox, StringVar, OptionMenu
import os

class AnnotationHandlerDialog:
    def __init__(self, handler_list):
        self.handler_list = handler_list
        self.success = False
        
        # Create the main window
        self.root = Tk()
        self.root.title("Export Format")
        
        # Create a frame for the combobox and buttons
        self.frame = Toplevel(self.root)
        self.frame.title("Select Annotation Handler")

        # Create the combobox
        self.handler_var = StringVar()
        self.handler_listbox = Listbox(self.frame, listvariable=self.handler_var)

        # Populate the combobox with handler names
        for i in range(len(handler_list)):
            self.handler_listbox.insert(i+1, str(handler_list[i]))

        # Create OK and Cancel buttons
        def ok_callback():
            selected_handler_index = int(self.handler_listbox.curselection()[0])
            if selected_handler_index > -1:
                self.success = True
                self.frame.destroy()
        
        def cancel_callback():
            self.frame.destroy()

        ok_button = Button(self.frame, text="OK", command=ok_callback)
        cancel_button = Button(self.frame, text="Cancel", command=cancel_callback)

        # Layout the frame
        Label(self.frame, text="Select Annotation Handler").pack()
        self.handler_listbox.pack()
        ok_button.pack(side='left')
        cancel_button.pack(side='right')

    def get_handler(self):
        return None

    def was_successful(self):
        return self.success


# Example usage:
handler_list = ["Handler 1", "Handler 2"]
dialog = AnnotationHandlerDialog(handler_list)
```

Please note that this is a simplified translation and may not exactly replicate the original Java code.