Here is the translation of the Java code to Python:
```
import threading

class TestThreadedTableModelListener:
    def __init__(self, model):
        self.spy = SpyEventRecorder("Listener Spy")
        self.model = model
        self.pending = False
        self.updating = False
        self.completed = False
        self.cancelled = False

    def reset(self, new_model=None):
        if new_model:
            self.model = new_model
        self.spy.record("Test - listener - reset()")
        self.completed = self.cancelled = False

    def done_work(self):
        self.spy.record(f"Test - listener - doneWork()? {self.completed or self.cancelled} - completed? {self.completed}; cancelled? {self.cancelled}")
        return self.completed or self.cancelled

    def started_work(self):
        self.spy.record("Test - listener - startedWork() - updating? " + str(self.updating))
        return self.updating

    def load_pending(self):
        self.pending = True
        self.spy.record("Swing - listener - loadPending")

    def loading_started(self):
        self.updating = True
        self.spy.record("Swing - listener - loadStarted")

    def loading_finished(self, was_cancelled=False):
        self.cancelled = was_cancelled
        if not was_cancelled:
            self.completed = True
        self.spy.record(f"Swing - listener - loadingFinished() - cancelled? {was_cancelled}; size: {self.model.get_row_count()}")

    def __str__(self):
        return f"{type(self).__name__}[pending={self.pending}, updating={self.updating}, completed={self.completed}, cancelled={self.cancelled}]"
```
Note that I had to make some assumptions about the `SpyEventRecorder` class, as it's not provided in the original Java code. In Python, you would typically use a logging library or a debugging tool like pdb to record events and debug your program.

Also, I used f-strings for string formatting, which is a feature introduced in Python 3.6. If you're using an earlier version of Python, you can use the `format()` method instead.