Here is the translation of the given Java code into Python:

```Python
from abc import ABCMeta, abstractmethod
import collections.abc as caba
import functools
import typing as t

class AncillaryFilterDialogComponentProvider(metaclass=ABCMeta):
    def __init__(self, controller: 'VTController', title: str, dialog_model: 'FilterDialogModel'):
        self.controller = controller
        self.dialog_model = dialog_model
        self.filter_changed_listener = None  # type: t.Callable[[t.Any], None]
        self.ancillary_filters = set()  # type: caba.Set[t.Type['AncillaryFilter']]
        self.original_state = collections.defaultdict(dict)  # type: dict

    def is_filtered(self):
        if self._is_filtered:
            return True
        self._is_filtered = False
        for filter_ in self.ancillary_filters:
            state = filter_.filter_shortcut_state()
            if state != 'ALWAYS_PASSES':
                self._is_filtered = True
                break
        return self._is_filtered

    def close(self):
        super().close()
        self.original_state.clear()
        self.dialog_model.dialog_visibility_changed(False)
        self.update_buttons(False)

    @abstractmethod
    def build_filter_panel(self) -> t.Any:
        pass

    def add_work_panel(self, panel: 'JComponent'):
        # todo implement this method
        pass

    def state_changed(self, state):
        has_changes = self.has_state_changed(state)
        self.update_buttons(has_changes)

    @abstractmethod
    def update_buttons(self, has_changes: bool) -> None:
        pass

    def apply_callback(self):
        self.apply_state(self.get_current_state())
        self.close()

    def cancel_callback(self):
        self.apply_state(self.original_state)
        self.close()

    def ok_callback(self):
        self.apply_state(self.get_current_state())
        self.close()
```

Note that I've used Python's type hints to indicate the types of variables and function parameters. This is not strictly necessary, but it can be helpful for other developers who may need to understand or modify your code.

Also note that some methods have been marked as abstract using the `@abstractmethod` decorator. These are intended to be implemented by subclasses of this class.