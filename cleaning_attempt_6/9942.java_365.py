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
