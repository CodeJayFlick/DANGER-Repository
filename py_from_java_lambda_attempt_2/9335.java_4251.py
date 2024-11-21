Here is a translation of the Java code into equivalent Python code:

```Python
import tkinter as tk
from typing import Any

class DisabledComponentLayerFactory:
    _disabled_ui = None  # private class variable

    def __init__(self):
        pass  # no-op constructor

    @classmethod
    def get_disabled_layer(cls, component: Any) -> Any:
        layer = JLayer(component, cls._get_or_create_disabled_ui())
        return layer

    @staticmethod
    def _get_or_create_disabled_ui() -> 'DisabledComponentLayerUI':
        if DisabledComponentLayerFactory._disabled_ui is None:
            DisabledComponentLayerFactory._disabled_ui = DisabledComponentLayerUI()
        return DisabledComponentLayerFactory._disabled_ui


class DisabledComponentLayerUI(tk.Frame):
    def __init__(self, master: Any) -> None:
        super().__init__(master)
        self.master = master

    def install(self, c: Any) -> None:
        if not isinstance(c, tk.Widget):  # equivalent to JComponent
            return
        for event in [tk.KEY_FOCUS_CHANGE, tk.MOUSE_MOTION]:
            c.bind(event, lambda e: "break")  # prevent focus and mouse events

    def uninstall(self, c: Any) -> None:
        if not isinstance(c, tk.Widget):  # equivalent to JComponent
            return
        for event in [tk.KEY_FOCUS_CHANGE, tk.MOUSE_MOTION]:
            c.unbind(event)

    @staticmethod
    def get_color_for_component(component: Any) -> str:
        if isinstance(component, (tk.Button, tk.OptionMenu)):
            return "Button.background"
        elif isinstance(component, tk.Menubutton):
            return "Menubutton.background"
        else:
            return "Panel.background"


class JLayer(tk.Frame):  # equivalent to JLayer
    def __init__(self, master: Any, ui: 'DisabledComponentLayerUI') -> None:
        super().__init__(master)
        self.master = master
        self.ui = ui

    @property
    def is_enabled(self) -> bool:
        return True


def main():
    root = tk.Tk()
    label = tk.Label(root, text="Hello")
    layer = DisabledComponentLayerFactory.get_disabled_layer(label)
    label.pack()
    root.mainloop()


if __name__ == "__main__":
    main()

```

Please note that the translation is not exact and some Java-specific features may be missing or modified.