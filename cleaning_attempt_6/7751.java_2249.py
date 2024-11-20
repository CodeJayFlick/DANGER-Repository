import threading
from typing import Any

class SetLayoutTask:
    def __init__(self, viewer: Any, layout_transition_manager: Any, layout_name: str):
        self.viewer = viewer
        self.layout_transition_manager = layout_transition_manager
        self.layout_name = layout_name

    def run(self) -> None:
        cancelled_listener = lambda: self.task_cancelled()
        monitor.add_cancelled_listener(cancelled_listener)

        model = self.viewer.get_visualization_model()
        layout_model = model.get_layout_model()
        support = layout_model.get_layout_state_change_support()
        listener = lambda e: self.layout_state_changed(e)
        support.add_layout_state_change_listener(listener)

        threading.Thread(target=lambda: self.layout_transition_manager.set_layout(self.layout_name)).start()

        self.wait_for_layout_transition(model)

        support.remove_layout_state_change_listener(listener)
        monitor.remove_cancelled_listener(cancelled_listener)

    def wait_for_layout_transition(self, model):
        graph = model.get_graph()
        if not graph.vertex_set():
            return

        try:
            self.task_done.await()
        except threading.InterruptError as e:
            model.get_layout_algorithm().cancel()

    def layout_state_changed(self, event: Any) -> None:
        if not event.active:
            self.task_done.count_down()

    def task_cancelled(self):
        self.task_done.count_down()
        self.viewer.get_visualization_model().get_layout_algorithm().cancel()


class TaskMonitor:
    def __init__(self):
        pass

    def add_cancelled_listener(self, listener: Any) -> None:
        pass

    def remove_cancelled_listener(self, listener: Any) -> None:
        pass


task_done = threading.Event()
