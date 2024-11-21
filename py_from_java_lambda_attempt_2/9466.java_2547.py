Here is the translation of the Java code to Python:
```python
import typing as t

class ShowAllComponentsAction:
    def __init__(self, win_mgr: object, info_list: t.List[object], sub_menu_name: str):
        self.info_list = info_list
        super().__init__(win_mgr, "Show All", sub_menu_name)

        group = "Z"
        menu_data = MenuData(["MENU_WINDOW", sub_menu_name, "Show All"], "", group)
        win_mgr.set_menu_group(["MENU_WINDOW", sub_menu_name], "Permanent")
        self.set_help_location("DockingWindows", "Windows_Menu")

    def actionPerformed(self, context: object):
        focus_me = True
        for info in self.info_list:
            if isinstance(info, ComponentPlaceholder):
                win_mgr.show_component(info, True, focus_me, True)
                focus_me = False

class MenuData:
    def __init__(self, menu_items: t.List[str], icon: str, group: str):
        self.menu_items = menu_items
        self.icon = icon
        self.group = group

class ComponentPlaceholder:
    pass  # No equivalent in Python, just a placeholder for now

# Example usage:
win_mgr = object()  # Replace with actual implementation
info_list = [ComponentPlaceholder(), ...]  # Replace with actual data
sub_menu_name = "My Submenu"
action = ShowAllComponentsAction(win_mgr, info_list, sub_menu_name)
```
Note that I had to make some assumptions about the Python equivalent of Java classes and methods. Specifically:

* `package` is not a concept in Python, so I omitted it.
* `import java.util.List;` was replaced with `typing as t`, which imports the `List` type from the `typing` module (Python 3.x).
* `MenuData` and `ComponentPlaceholder` are simple classes that don't have direct equivalents in Java. In Python, they can be represented as plain old data structures.
* The rest of the code is translated to Python using standard syntax.

Please note that this translation may not cover all edge cases or nuances of the original Java code.