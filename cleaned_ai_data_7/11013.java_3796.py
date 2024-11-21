import threading

class LockingTaskMonitor:
    def __init__(self, dobj, has_progress, title):
        self.dobj = dobj
        self.has_progress = has_progress
        self.title = title
        self.is_canceled = False
        self.cancel_enabled = True
        self.indeterminate = None
        self.show_progress_value = True

    def get_domain_object(self):
        return self.dobj

    def wait_for_task_completion(self):
        if not self.dobj:
            return
        if not self.task_dialog:
            self.task_dialog = MyTaskDialog()
        else:
            try:
                # dialog already displayed - wait for release_lock to occur
                lock = threading.Lock()
                with lock:
                    while True:
                        if self.is_canceled or self.release_lock():
                            break
            except Exception as e:
                pass

    def is_cancelled(self):
        return bool(self.task_dialog and self.task_dialog.is_cancelled() or self.is_canceled)

    def release_lock(self):
        if not self.dobj:
            return False
        try:
            self.dobj.unlock(self)
            self.dobj = None
            self.task_dialog.task_processed()
            self.task_dialog = None
            lock = threading.Lock()
            with lock:
                lock.notify_all()
            return True
        except Exception as e:
            pass

    def set_message(self, msg):
        if not self.msg or self.msg != msg:
            self.msg = msg
            if self.task_dialog and self.msg:
                self.task_dialog.set_message(msg)

    def get_message(self):
        return self.msg

    def set_progress(self, value):
        if self.cur_progress == value:
            return
        try:
            lock = threading.Lock()
            with lock:
                self.cur_progress = value
                if self.task_dialog and self.show_progress_value:
                    self.task_dialog.set_progress(value)
        except Exception as e:
            pass

    def initialize(self, max):
        if not self.max_progress or self.max != max:
            try:
                lock = threading.Lock()
                with lock:
                    self.max_progress = max
                    self.cur_progress = 0
                    if self.task_dialog and self.has_progress:
                        self.task_dialog.initialize(max)
            except Exception as e:
                pass

    def set_maximum(self, value):
        if not self.max_progress or self.max != value:
            try:
                lock = threading.Lock()
                with lock:
                    self.max_progress = value
                    if self.task_dialog and self.has_progress:
                        self.task_dialog.set_maximum(value)
            except Exception as e:
                pass

    def get_maximum(self):
        return self.max_progress

    def set_indeterminate(self, indeterminate):
        try:
            lock = threading.Lock()
            with lock:
                self.indeterminate = indeterminate
                if self.task_dialog and self.has_progress:
                    self.task_dialog.set_indeterminate(indeterminate)
        except Exception as e:
            pass

    def is_indeterminate(self):
        return bool(self.indeterminate)

    def set_cancel_enabled(self, enable):
        try:
            lock = threading.Lock()
            with lock:
                self.cancel_enabled = enable
                if self.task_dialog and self.has_progress:
                    self.task_dialog.set_cancel_enabled(enable)
        except Exception as e:
            pass

    def is_cancel_enabled(self):
        return bool(self.task_dialog and self.task_dialog.is_cancel_enabled() or self.cancel_enabled)

    def cancel(self):
        try:
            lock = threading.Lock()
            with lock:
                if not self.dobj:
                    return
                self.is_canceled = True
                if self.task_dialog:
                    self.task_dialog.cancel()
        except Exception as e:
            pass

    def clear_cancelled(self):
        try:
            lock = threading.Lock()
            with lock:
                self.is_canceled = False
                if self.task_dialog:
                    self.task_dialog.clear_cancelled()
        except Exception as e:
            pass

    def check_cancelled(self):
        if self.is_cancelled():
            raise CancelledException()

    def increment_progress(self, value):
        try:
            lock = threading.Lock()
            with lock:
                self.set_progress(self.cur_progress + value)
        except Exception as e:
            pass

    def get_progress(self):
        return self.cur_progress


class MyTaskDialog(threading.Thread):
    def __init__(self):
        super().__init__()
        self.title = None
        self.has_progress = False
        self.cancel_enabled = True
        self.show_progress_value = True
        self.max_progress = 0

    def run(self):
        while True:
            if not self.is_cancelled():
                break
        lock = threading.Lock()
        with lock:
            print("Task processed")


class CancelledException(Exception):
    pass


if __name__ == "__main__":
    dobj = None
    has_progress = False
    title = "My Task"
    monitor = LockingTaskMonitor(dobj, has_progress, title)
    task_dialog = MyTaskDialog()
    task_dialog.start()

