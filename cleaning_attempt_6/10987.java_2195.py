class BackgroundCommand:
    def __init__(self):
        self.name = "no-name"
        self.has_progress = False
        self.can_cancel = False
        self.is_modal = False
        self.status_msg = ""

    def apply_to(self, obj):
        return self.apply_to(obj, None)

    def apply_to(self, obj, monitor=None):
        raise NotImplementedError("This method must be implemented by the subclass")

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def has_progress(self):
        return self._has_progress

    @has_progress.setter
    def has_progress(self, value):
        self._has_progress = value

    @property
    def can_cancel(self):
        return self._can_cancel

    @can_cancel.setter
    def can_cancel(self, value):
        self._can_cancel = value

    @property
    def is_modal(self):
        return self._is_modal

    @is_modal.setter
    def is_modal(self, value):
        self._is_modal = value

    @property
    def status_msg(self):
        return self._status_msg

    @status_msg.setter
    def status_msg(self, value):
        self._status_msg = value

    def dispose(self):
        pass  # do nothing by default

    def task_completed(self):
        pass  # do nothing by default

    def __str__(self):
        return self.name
