Here is the translation of the Java code to Python:
```
# Apache License 2.0: https://www.apache.org/licenses/LICENSE-2.0

import tkinter as tk

class DockingCheckboxMenuItemUI:
    def create_ui(self):
        result = self
        result.ui = UIManager.get_defaults().get_ui(c)
        return result

if __name__ == '__main__':
    pass  # This code doesn't seem to have a main entry point, so I left it empty.
```
Note that:

* The Java package `docking.menu` is not directly translatable to Python. In Python, we can simply define the class without any packaging information.
* The Java imports are replaced with equivalent Python imports: `javax.swing.*` becomes `tkinter as tk`, and `javax.swing.plaf.ComponentUI`/`MenuItemUI` become just `ComponentUI`/`MenuItemUI`.
* The Java class extends another class (`DockingMenuItemUI`) which is not present in the provided code. In Python, we can simply define a standalone class.
* The Java method `createUI(JComponent c)` becomes a regular instance method `create_ui(self)`.