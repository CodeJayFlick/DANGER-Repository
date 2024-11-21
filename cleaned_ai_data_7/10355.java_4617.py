import logging

class ClassLocation:
    CLASS_EXT = ".class"

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.classes = set()

    def get_classes(self, existing_classes: set) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def check_for_duplicates(self, existing_classes: set) -> None:
        if not self.logger.isEnabledFor(logging.TRACE):
            return

        for c in self.classes:
            if c in existing_classes:
                module = c.__module__
                self.logger.trace(f"Attempting to load the same class twice: {c}. Keeping loaded class ; ignoring class from {self}")
