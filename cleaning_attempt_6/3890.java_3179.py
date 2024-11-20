class StackDepthChangeListener:
    def __init__(self):
        pass

    def actionPerformed(self, event: 'StackDepthChangeEvent'):
        # Your action performed code here
        pass


from abc import ABC, abstractmethod


class EventListener(ABC):
    @abstractmethod
    def process_event(self, event):
        pass


class StackDepthChangeEvent:
    pass
