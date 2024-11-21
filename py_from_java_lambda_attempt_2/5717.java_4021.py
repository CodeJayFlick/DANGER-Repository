Here is the translation of the Java code to Python:
```
import tkinter as tk

class FixedLengthTextField(tk.Text):
    def __init__(self, text="", size_component=None):
        super().__init__()
        self.insert("1.0", text)
        if size_component:
            self.size_component = size_component
        else:
            self.size_component = None

    def get_preferred_size(self):
        insets = self.size_component.insets()
        textSize = tk.Dimension(
            width=self.size_component.width - insets.left,
            height=super().get_preferred_size().height)
        super().set_preferred_size(textSize)
        return textSize
```
Note that I used the `tkinter` library, which is Python's de-facto standard GUI library. The code translates to a subclass of `tk.Text`, with similar methods and attributes as in the original Java code.

Here are some key differences between the two languages:

* In Python, we use the `super()` function to call the parent class's method.
* We don't need explicit type declarations or casts like in Java. The `size_component` attribute is assigned a value of `None` if not provided, which is equivalent to Java's null assignment.
* The `get_preferred_size()` method returns a `tk.Dimension` object instead of an array-like structure (Java's Dimension class).
* We use the `.insert()` method to set the initial text in the field.

I hope this helps! Let me know if you have any further questions.