class DiffTaskListener:
    NULL_LISTENER = lambda: None  # No-op listener that does nothing when task in progress changes.

    def __init__(self):
        pass

    def task_in_progress(self, in_progress: bool) -> None:
        """Signal the start and end of a diff task."""
        pass
