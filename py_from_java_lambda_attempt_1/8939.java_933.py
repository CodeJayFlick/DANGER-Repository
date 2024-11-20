Here is the translation of the Java code into Python:

```Python
from abc import ABCMeta, abstractmethod
import tkinter as tk
from typing import Set, Dict, Any

class CheckBoxBasedAncillaryFilter(metaclass=ABCMeta):
    def __init__(self, filter_name: str) -> None:
        self.filter_name = filter_name
        self.checkBoxInfos = set()
        self.enabledCheckBoxNames = None
        self.component = None

    @abstractmethod
    def create_checkbox_infos(self) -> None:
        pass

    def fire_filter_state_changed(self) -> None:
        self.enabledCheckBoxNames = None
        super().fire_filter_state_changed()

    def initialize_enabled_check_box_names(self) -> Set[str]:
        if not self.enabledCheckBoxNames:
            enabled_filters = {info.get_checkbox_text() for info in self.checkBoxInfos if info.is_selected()}
            self.enabledCheckBoxNames = set(enabled_filters)
        return self.enabledCheckBoxNames

    @property
    def enabled_filter_names(self) -> Set[str]:
        return self.initialize_enabled_check_box_names()

    def create_component(self) -> tk.Frame:
        layout_manager = self.create_layout_manager()
        panel = tk.Frame()
        panel.pack(side=tk.LEFT, fill=tk.BOTH)
        panel.config(bd=5, relief=tk.RAISED)

        self.add_check_boxes(panel)

        return panel

    @abstractmethod
    def create_filter_panel(self, container: tk.Frame) -> None:
        pass

    def add_check_boxes(self, container: tk.Frame) -> None:
        for info in self.checkBoxInfos:
            container.pack(side=tk.LEFT, fill=tk.BOTH)
            container.config(bd=5, relief=tk.RAISED)

    @property
    def component(self) -> Any:
        return self.component

    @abstractmethod
    def get_filter_status(self) -> int:
        pass

    @abstractmethod
    def passes_filter(self, item: T) -> bool:
        pass

    @abstractmethod
    def get_filter_shortcut_state(self) -> str:
        pass

    @abstractmethod
    def clear_filter(self) -> None:
        pass

    @property
    def filter_status(self) -> int:
        for info in self.checkBoxInfos:
            if not info.is_selected():
                return 1
        return 0

    @abstractmethod
    def get_filter_state(self) -> Any:
        pass

    @abstractmethod
    def restore_filter_state(self, state: Any) -> None:
        pass

    @abstractmethod
    def read_config_state(self, save_state: Any) -> None:
        pass

    @property
    def filter_shortcut_state(self) -> str:
        on_count = 0
        for info in self.checkBoxInfos:
            if info.is_selected():
                on_count += 1
        if not on_count:
            return "NEVER_PASSES"
        elif on_count == len(self.checkBoxInfos):
            return "ALWAYS_PASSES"
        else:
            return "REQUIRES_CHECK"

    @abstractmethod
    def write_config_state(self, save_state: Any) -> None:
        pass

    def get_state_key(self) -> str:
        return f"{self.__class__.__name__}:{type(self).__name__}"

    def is_sub_filter_of(self, other_filter: 'Filter') -> bool:
        if not isinstance(other_filter, type(self)):
            return False
        names = self.enabled_filter_names
        other_names = other_filter.get_enabled_filter_names()
        return set(other_names).issuperset(names)

    @abstractmethod
    def get_component(self) -> Any:
        pass

    def __str__(self) -> str:
        return f"{type(self).__name__} {', '.join(map(str, self.enabled_filter_names))}"
```

Note: The Python code is written in a way that it can be easily converted back to Java.