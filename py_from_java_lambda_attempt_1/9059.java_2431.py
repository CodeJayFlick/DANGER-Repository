Here is the translation of the Java code into Python:

```Python
class VtTask:
    MAX_ERRORS = 10

    def __init__(self, title: str, session):
        self.session = session
        super().__init__()

    def run(self, monitor):
        if self.session and should_suspend_session_events():
            self.session.set_events_enabled(False)
        try:
            success = self.do_work(monitor)
        except CancelledException as e:
            self.cancelled = True
        except Exception as e:
            self.report_error(e)

        finally:
            if self.session and restore_events:
                self.session.set_events_enabled(True)

    def should_suspend_session_events(self):
        return False

    @abstractmethod
    def do_work(self, monitor) -> bool:
        pass

    @property
    def was_cancelled(self):
        return self.cancelled

    @property
    def was_successful(self):
        return self.success

    @property
    def has_errors(self):
        return not self.errors.empty()

    def show_errors(self):
        if not self.errors:
            return
        title = self.get_error_dialog_title()
        message = self.get_error_details()
        Msg.show_error(None, None, title, message)

    def get_error_header(self):
        return f"Errors encountered for task '{self.get_task_title()}':"

    def log_errors(self):
        if not self.errors:
            return
        buf = StringBuilder(f"{self.get_error_header()}\n")
        for error in self.errors:
            buf.append("\t").append(error).append("\n")
        Msg.error(None, str(buf))

    @property
    def get_task_title(self) -> str:
        pass

    def get_error_dialog_title(self):
        if self.success:
            return f"Task '{self.get_task_title()}' Partially Completed"
        return f"Task Failed: {self.get_task_title()}"

    def get_error_details(self) -> str:
        buf = StringBuilder("<html>" + self.get_error_header())
        error_count = 0
        buf.append("<blockquote><br>")
        for error in self.errors:
            buf.append(error).append("<br>")
            if ++error_count > VtTask.MAX_ERRORS:
                buf.append(f"...and {len(self.errors) - error_count} more!")
                break
        return str(buf)

    def report_error(self, e):
        message = str(e)
        if not message:
            message = f"Unexpected Exception: {str(e)}"
        self.errors.add(message)

    @property
    def get_task_title(self) -> str:
        pass

    def add_errors(self, task):
        self.errors.extend(task.errors)


class StringBuilder:
    def __init__(self, initial_value=""):
        self.value = initial_value

    def append(self, value):
        self.value += str(value)

    @property
    def empty(self) -> bool:
        return not self.value


import java.util.ArrayList;
import ghidra.feature.vt.api.main.VTSession;
```

Note: Python does not have direct equivalent of Java's StringBuilder class. In this translation, I used a simple string concatenation to build the error message.