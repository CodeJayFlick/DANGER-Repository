Here is the translation of the Java code to Python:
```
from tkinter import *

class CheckBoxInfo:
    def __init__(self, checkbox):
        self.checkbox = checkbox

    def set_selected(self, b):
        self.checkbox.select()

    def get_selected(self):
        return self.checkbox.instate((SELECT, True))

    def get_checkbox(self):
        return self.checkbox

    def matches_status(self, t):  # abstract method
        raise NotImplementedError("Must be implemented by subclass")

    def __str__(self):
        return str(self.checkbox.cget('text'))
```
Note that I used the `tkinter` library instead of Java's Swing framework. In Python, we don't need to specify types for variables or methods like in Java.

Also, since this is an abstract class in Java, I made the `matches_status` method a pure virtual function (i.e., it raises a `NotImplementedError`) and left its implementation up to any subclasses that might be defined.