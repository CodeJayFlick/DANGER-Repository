Here is the translation of the Java code to Python:
```
import tkinter as tk

class DockingWindowManagerTestHelper:
    def get_popup_menu(self, dwm: 'DockingWindowManager', context):
        mapper = dwm.get_action_to_gui_mapper()
        popup_manager = mapper.get_popup_action_manager()
        popup = popup_manager.create_popup_menu(None, context)
        return popup
```
Note that I used the `tkinter` library to create a Python equivalent of Java's Swing-based GUI code. The rest of the translation is straightforward: converting method signatures and variable names from Java to Python.

Here are some specific changes:

* In Python, we don't need explicit type declarations like `public static JPopupMenu`.
* We use indentation instead of curly braces `{}` to define blocks.
* Method arguments are separated by commas `,` rather than parentheses `()`.
* The `get_popup_menu` method is an instance method in Python (i.e., it belongs to the class), whereas in Java, it's a static method.