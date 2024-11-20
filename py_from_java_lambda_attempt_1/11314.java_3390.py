Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABC, abstractmethod

class AbstractTaskInfo(ABC):
    def __init__(self, group: 'GTaskGroup', use_animation: bool) -> None:
        self.group = group
        self.use_animation = use_animation
        self.background_animator = None
        self.component = None

    @abstractmethod
    def get_label_text(self) -> str:
        pass

    def get_group(self) -> 'GTaskGroup':
        return self.group

    def compare_to(self, other: 'AbstractTaskInfo') -> int:
        result = self.get_group().compare_to(other.get_group())
        if result == 0:
            if isinstance(self, GroupInfo):
                return -1
            elif isinstance(other, GroupInfo):
                return 1
            else:
                my_task = (self).get_scheduled_task()
                other_task = (other).get_scheduled_task()
                return my_task.compare_to(other_task)
        return result

    def get_component(self) -> 'ScheduledTaskPanel':
        if self.component is None:
            self.component = ScheduledTaskPanel(get_label_text(), get_indention())
            if self.use_animation:
                start_color = Color('yellow')
                end_color = Color('white')
                self.background_animator = PropertySetter.create_animator(4000, self, 'Background', start_color, end_color)
                self.background_animator.start()
        return self.component

    def set_background(self, c: 'Color') -> None:
        if self.component is not None:
            self.component.set_background(c)

    @abstractmethod
    def get_indention(self) -> int:
        pass

    def set_running(self) -> 'GProgressBar':
        progress_bar = self.get_component().add_progress_bar()
        if self.background_animator is not None:
            self.background_animator.stop()
            self.component.set_background(Color('white'))
            self.background_animator = None
        return progress_bar

    def set_scroll_fraction(self, fraction: float) -> None:
        self.component.set_hidden_view_amount(fraction)
        self.component.invalidate()
        parent = self.component.get_parent()
        if parent is not None:
            grandparent = parent.get_parent()
            if grandparent is not None:
                grandparent.validate()

class ScheduledTaskPanel(ABC):
    def __init__(self, label_text: str, indention: int) -> None:
        pass

    @abstractmethod
    def add_progress_bar(self) -> 'GProgressBar':
        pass

    @abstractmethod
    def set_hidden_view_amount(self, fraction: float) -> None:
        pass

    @abstractmethod
    def invalidate(self) -> None:
        pass

    @abstractmethod
    def get_parent(self) -> 'Container':
        pass

class GTaskGroup(ABC):
    @abstractmethod
    def compare_to(self, other: 'GTaskGroup') -> int:
        pass

    @abstractmethod
    def get_scheduled_task(self) -> 'GScheduledTask':
        pass

class GScheduledTask(ABC):
    @abstractmethod
    def compare_to(self, other: 'GScheduledTask') -> int:
        pass

class Color:
    def __init__(self, color_name: str) -> None:
        self.color = color_name

    def get_color(self) -> str:
        return self.color

class GProgressBar(ABC):
    @abstractmethod
    def add_progress_bar(self) -> 'GProgressBar':
        pass

    @abstractmethod
    def set_hidden_view_amount(self, fraction: float) -> None:
        pass

    @abstractmethod
    def get_parent(self) -> 'Container':
        pass