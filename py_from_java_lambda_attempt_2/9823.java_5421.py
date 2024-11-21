Here is the translation of the Java code to Python:
```
import tkinter as tk

class GTableTextCellEditor:
    TABLE_FOCUSED_CELL_HIGHLIGHT_BORDER = "TABLE_FOCUSED_CELL_HIGHLIGHT_BORDER"

    def __init__(self, text_field):
        super().__init__()
        self.set_click_count_to_start(2)

        text_field.config(border=tk.get_border(TABLE_FOCUSED_CELL_HIGHLIGHT BORDER))

# Example usage:
text_field = tk.Text()
editor = GTableTextCellEditor(text_field)
```
Note that I used the `tkinter` library, which is Python's de-facto standard GUI library. The code assumes you have a basic understanding of Python and tkinter.

Here are some key differences between Java and Python:

* In Python, we don't need to declare variables or methods beforehand.
* We use the `super()` function to call the parent class constructor (equivalent to `DefaultCellEditor` in Java).
* The `set_click_count_to_start(2)` method is not a standard tkinter method. I assume it's meant to set some property related to mouse clicks, but without more context, I couldn't replicate its exact behavior.
* In Python, we use the `.config()` method to modify widget properties (equivalent to Java's `setBorder()`).
* The `TABLE_FOCUSED_CELL_HIGHLIGHT_BORDER` constant is not a standard tkinter constant. If you need this specific border style, you'll have to create it yourself or find an equivalent in tkinter.

Keep in mind that Python and Java are different languages with their own strengths and weaknesses. This translation may require adjustments depending on your specific use case.