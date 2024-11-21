class TaskMonitor:
    def __init__(self):
        self.max = 1000000
        self.progress = 0

    def initialize(self, size):
        pass

    def increment_progress(self, amount):
        if self.max > 0:
            self.progress += amount
            if self.progress > self.max:
                self.progress = self.max
        return self.get_progress()

    def get_maximum(self):
        return self.max

    def get_progress(self):
        return self.progress


class SubTaskMonitor(TaskMonitor, CancelledListener):
    def __init__(self, parent, sub_size, shared_set):
        self.parent = parent
        self.sub_size = sub_size
        shared_set.add(self)

    def add_cancelled_listener(self, listener):
        if not hasattr(self, 'listeners'):
            self.listeners = []
        self.listeners.append(listener)
        return self

    def cancel(self):
        self.parent.cancel()

    def check_canceled(self):
        self.parent.check_canceled()

    def clear_canceled(self):
        raise NotImplementedError("Method is not implemented")

    def get_maximum(self):
        return self.max

    def get_progress(self):
        return self.progress

    def increment_progress(self, amount):
        if self.max > 0:
            self.progress += amount
            if self.progress > self.max:
                self.progress = self.max
        else:
            self.parent.increment_progress(amount)
        return self.get_progress()

    def normalize_progress(self):
        pass

    def update_parent(self):
        new_parent_progress = int((self.progress * self.sub_size) / self.max)
        self.parent.increment_progress(new_parent_progress - self.parent.progress)
        self.parent.progress = new_parent_progress
        return self

    def is_cancel_enabled(self):
        return self.parent.is_cancel_enabled()

    def is_canceled(self):
        return self.parent.is_canceled()

    def remove_cancelled_listener(self, listener):
        if hasattr(self, 'listeners'):
            self.listeners.remove(listener)
        return self

    def set_cancel_enabled(self, enable):
        self.parent.set_cancel_enabled(enable)

    def show_progress_value(self):
        pass

    def set_indeterminate(self, indeterminate):
        self.parent.set_indeterminate(indeterminate)

    def is_indeterminate(self):
        return self.parent.is_indeterminate()

    def initialize(self, new_max):
        if hasattr(self, 'max'):
            delattr(self, 'max')
        setattr(self, 'progress', 0)
        self.max = new_max
        self.normalize_progress()
        self.update_parent()
        return self

    def set_maximum(self, new_max):
        self.max = new_max
        self.normalize_progress()
        self.update_parent()

    def message(self):
        pass

    def get_message(self):
        return self.parent.get_message()

    def set_progress(self, value):
        if hasattr(self, 'max'):
            delattr(self, 'progress')
        setattr(self, 'progress', value)
        self.normalize_progress()
        self.update_parent()

    def cancelled(self):
        for listener in getattr(self, 'listeners', []):
            listener.cancelled()


class CancelledListener:
    pass
