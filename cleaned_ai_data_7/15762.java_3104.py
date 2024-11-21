class Progress:
    def __init__(self):
        self.message = None
        self.max = 0
        self.trailing_message = None
        self.initial_progress = 0

    def reset(self, message: str, max: int, trailing_message=None) -> None:
        self.message = message
        self.max = max
        self.trailing_message = trailing_message

    def start(self, initial_progress: int) -> None:
        if not hasattr(self, 'initial_progress'):
            self.initial_progress = 0
        self.update(initial_progress)

    def end(self) -> None:
        pass  # No equivalent in Python. This method is used to indicate the task completion.

    def increment(self, increment: int) -> None:
        current_progress = getattr(self, 'current_progress', 0)
        new_progress = min(current_progress + increment, self.max)
        if hasattr(self, 'update'):
            self.update(new_progress)

    @property
    def current_progress(self):
        return getattr(self, '_progress', 0)

    @current_progress.setter
    def current_progress(self, value: int) -> None:
        self._progress = min(value, self.max)

    def update(self, progress: int, message=None) -> None:
        if hasattr(self, 'update'):
            super().update(progress)
