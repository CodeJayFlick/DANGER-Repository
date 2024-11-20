Here is the translation of the given Java code into Python:

```Python
from abc import ABC, abstractmethod
import typing as t

class AbstractWizardJPanel:
    def __init__(self):
        self.listeners = []

    def add_listener(self, listener: 'AbstractWizardJPanelListener'):
        if not self.listeners.__contains__(listener):
            self.listeners.append(listener)

    def remove_listener(self, listener: 'AbstractWizardJPanelListener'):
        self.listeners.remove(listener)

    @abstractmethod
    def notify_listeners_of_validity_changed(self):
        pass

    @abstractmethod
    def notify_listeners_of_status_message(self, msg: str):
        pass


class AbstractWizardJPanelListener:
    @abstractmethod
    def validity_changed(self):
        pass

    @abstractmethod
    def set_status_message(self, msg: str):
        pass


# Example usage:

class ConcreteAbstractWizardJPanel(AbstractWizardJPanel):
    def notify_listeners_of_validity_changed(self):
        for listener in self.listeners:
            listener.validity_changed()

    def notify_listeners_of_status_message(self, msg: str):
        for listener in self.listeners:
            listener.set_status_message(msg)


# Example usage:

class ConcreteAbstractWizardJPanelListener(AbstractWizardJPanelListener):
    def validity_changed(self):
        print("Validity changed")

    def set_status_message(self, msg: str):
        print(f"Status message is {msg}")
```

This Python code defines two abstract classes (`AbstractWizardJPanel` and `AbstractWizardJPanelListener`) that are similar to the Java code. The main differences between this Python code and the original Java code are:

1.  In Python, we don't need explicit getters and setters for attributes.
2.  We use type hints in Python (e.g., `def notify_listeners_of_validity_changed(self): -> None`) but these do not affect runtime behavior; they only provide information to tools like IDEs or linters about the expected types of variables, function parameters, etc.

The provided Java code is a part of the Ghidra reverse engineering tool.