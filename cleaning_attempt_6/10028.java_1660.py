import logging

class ThreadedTableModelWorkerListener:
    def __init__(self, spy: 'SpyEventRecorder', model: 'ThreadedTableModel'):
        self.spy = spy
        self.model = model

    def progress_changed(self, id: int, item: object, progress: int):
        self.spy.record(f"Table Queue - progressChanged() - {item}; progress: {progress}")

    def task_started(self, id: int, item: object):
        self.spy.record(f"Table Queue - taskStarted() - {item}")

    def task_ended(self, id: int, item: object, total_count: int, completed_count: int):
        self.spy.record(
            f"Table Queue - taskEnded() - {item}; total submitted items: {total_count}"
        )
        self.dump_model()

    def progress_mode_changed(self, id: int, item: object, indeterminate: bool):
        self.spy.record(f"Table Queue - progressModeChanged() - {item}; is indeterminate: {indeterminate}")

    def max_progress_changed(self, id: int, item: object, max_progress: int):
        self.spy.record(
            f"Table Queue - maxProgressChanged() - {item}; max progress: {max_progress}"
        )

    def progress_message_changed(self, id: int, item: object, message: str):
        self.spy.record(f"Table Queue - progressMessageChanged() - {item}; message: {message}")

    def dump_model(self):
        all_data = list(self.model.get_all_data())
        buffy = f"\n\tRow count: {len(all_data)}"
        for t in all_data:
            buffy += f"\trow value: {str(t)}\n"
        self.spy.record(buffy)
