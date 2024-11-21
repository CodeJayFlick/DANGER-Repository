Here is the translation of the Java code into Python:

```Python
import threading
from tkinter import *

class TaskViewer:
    def __init__(self, task_manager):
        self.task_manager = task_manager
        self.build_component()
        self.task_listener = TaskViewerTaskListener(self)
        self.update_components_runnable = UpdateComponentsRunnable(self)
        self.update_manager = SwingUpdateManager(MIN_DELAY, MAX_DELAY, self.update_components_runnable)

    def set_use_animations(self, b):
        self.use_animations = b

    def build_component(self):
        self.task_viewer_component = TaskViewerComponent()
        self.layered-pane = JLayeredPane()
        self.layered-pane.setLayout(CustomLayoutManager())
        scroll = JScrollPane(self.task_viewer_component)
        self.layered-pane.add(scroll, JLayeredPane.DEFAULT_LAYER)
        self.layered-pane.add(MessageCanvas(), JLayeredPane.PALETTE_LAYER)

    def get_component(self):
        return self.layered-pane

    def start_scrolling_away_animation(self, start_delay):
        if not self.scroll-away-list.isEmpty():
            if not self.scroll-away-animator.is_running():
                self.scroll-away-animator.set_start_fraction(0)
                self.scroll-away-animator.set_duration(get_desired_duration())
                self.scroll-away-animator.set_start_delay(start_delay)
                self.scroll-away-animator.start()

    def update_component(self):
        if not threading.main_thread().is_alive():
            raise AssertionError("Must be in swing thread")
        self.task_viewer_component.removeAll()
        for element in self.running-list:
            self.task_viewer_component.add(element.get_component())
        if len(self.waiting-list) > 0 and len(self.running-list) > 0:
            self.task_viewer_component.add(JSeparator())
        for element in self.waiting-list:
            self.task_viewer_component.add(element.get_component())

    def initialize_running_element(self, task_info):
        g_progress_bar = task_info.set_running()
        g_task_monitor = task_info.get_scheduled_task().get_task_monitor()
        g_task_monitor.set_progress_bar(g_progress_bar)
        if task_info.get_group().was_cancelled():
            g_progress_bar.initialize(1)
            g_progress_bar.setMessage("CANCELLED!")
        self.running-list.add(task_info)

    def get_desired_duration(self):
        size = len(self.scroll-away-list)
        if size < 4:
            return 3000
        elif size < 6:
            return 2000
        elif size < 8:
            return 1000
        elif size < 10:
            return 500
        else:
            return 250

class CustomLayoutManager:
    def add_layout_component(self, name, comp):
        pass

    def remove_layout_component(self, comp):
        pass

    def preferred_layout_size(self, parent):
        insets = parent.getInsets()
        d = Dimension()
        for comp in parent.getComponents():
            size = comp.getPreferredSize()
            d.width = max(d.width, size.width)
            d.height = max(d.height, size.height)
        d.width += insets.left + insets.right
        d.height += insets.top + insets.bottom
        return d

    def minimum_layout_size(self, parent):
        return self.preferred_layout_size(parent)

    def layout_container(self, parent):
        size = parent.getSize()
        insets = parent.getInsets()
        width = size.width - insets.left - insets.right
        height = size.height - insets.top - insets.bottom
        x = insets.left
        y = insets.top
        for comp in parent.getComponents():
            comp.setBounds(x, y, width, height)

class MessageCanvas(Canvas):
    def __init__(self):
        super().__init__()

    def paint_component(self, g):
        if not self.task_manager.is_suspended():
            return
        g.setcomposite(scrolled_text_alpha_composite)
        font = Font("Sanf Serif", Font.BOLD, 36)
        g.setFont(font)
        g.setColor(Color(0, 0, 200))
        if self.message_dimension is None:
            font_metrics = get_font_metrics(self, font)
            self.message_dimension = font_metrics.getStringBounds(TEXT).getBounds()
        size = self.getSize()
        center_y = size.height / 2
        center_x = size.width / 2

        x = center_x - self.message_dimension.width / 2
        y = center_y + self.message_dimension.height / 2
        graphics_utils.draw_string(self, g, TEXT, x, y)

class TaskViewerTaskListener:
    def __init__(self):
        pass

    def initialize(self):
        self.runnable_queue.append(InitializeRunnable())
        self.update_manager.update_now()

    def task_started(self, scheduled_task):
        self.runnable_queue.append(TaskStartedRunnable(scheduled_task))
        self.update_manager.update()

    def task_completed(self, scheduled_task, result):
        self.runnable_queue.append(TaskCompletedRunnable(scheduled_task))
        self.update_manager.update()

    def task_group_scheduled(self, group):
        self.runnable_queue.append(TaskGroupScheduledRunnable(group))
        self.update_manager.update()

    def task_scheduled(self, scheduled_task):
        self.runnable_queue.append(TaskScheduledRunnable(scheduled_task))
        self.update_manager.update()

    def task_group_started(self, group):
        self.runnable_queue.append(TaskGroupStartedRunnable(group))
        self.update_manager.update()

    def task_group_completed(self, group):
        self.runnable_queue.append(TaskGroupCompletedRunnable(group))
        self.update_manager.update()

class InitializeRunnable:
    def __init__(self):
        pass

    def run(self):
        self.waiting-list.clear()
        if current_group is not None:
            running_list.add(GroupInfo(current_group))
            for scheduled_task in delayed_tasks:
                initialize_running_element(TaskInfo(scheduled_task))
            if running_task is not None:
                initialize_running_element(TaskInfo(running_task))
            for scheduled_task in scheduled_tasks:
                waiting-list.append(TaskInfo(scheduled_task))

    def run(self):
        self.waiting-list.clear()
        if current_group is not None:
            running_list.add(GroupInfo(current_group))
            for scheduled_task in delayed_tasks:
                initialize_running_element(TaskInfo(scheduled_task))
            if running_task is not None:
                initialize_running_element(TaskInfo(running_task))
            for scheduled_task in scheduled_tasks:
                waiting-list.append(TaskInfo(scheduled_task))

class TaskStartedRunnable:
    def __init__(self, task):
        self.task = task

    def run(self):
        iterator = waiting_list.iterator()
        while iterator.hasNext():
            info = iterator.next()
            if not (info instanceof TaskInfo):
                continue
            task_info =  (TaskInfo) info
            if task_info.get_scheduled_task() == self.task:
                iterator.remove()
                initialize_running_element(task_info)
                return

class TaskCompletedRunnable:
    def __init__(self, scheduled_task):
        self.scheduled_task = scheduled_task

    def run(self):
        running_list_iterator = running-list.iterator()

        while running_list_iterator.hasNext():
            info = running_list_iterator.next()
            if not (info instanceof TaskInfo):
                continue
            task_info =  (TaskInfo) info
            if task_info.get_scheduled_task() == self.scheduled_task:
                if use_animations:
                    scroll-away-list.add(info)
                    start_scrolling_away_animation(2000)
                else:
                    running_list_iterator.remove()
                return

        waiting_list_iterator = waiting-list.iterator()

        while waiting_list_iterator.hasNext():
            info = waiting_list_iterator.next()
            if not (info instanceof TaskInfo):
                continue
            task_info =  (TaskInfo) info
            if task_info.get_scheduled_task() == self.scheduled_task:
                running_list_iterator.remove()
                return

class TaskGroupScheduledRunnable:
    def __init__(self, group):
        self.group = group

    def run(self):
        waiting-list.add(GroupInfo(group))
        for scheduled_task in tasks:
            waiting-list.append(TaskInfo(scheduled_task))

class TaskScheduledRunnable:
    def __init__(self, task):
        self.task = task

    def run(self):
        if not use_animations or  (not running_list.isEmpty() and not waiting_list.isEmpty()):
            first = waiting-list.removeFirst()
            if first.get_group() != group:
                first = waiting-list.removeFirst()

class TaskGroupStartedRunnable:
    def __init__(self, group):
        self.group = group

    def run(self):
        iterator = running_list.iterator()
        while iterator.hasNext():
            info = iterator.next()
            g_task_monitor.set_progress_bar(g_progress-bar)
            if task_info.get_group() == self.group and  (info instanceof GroupInfo):
                return