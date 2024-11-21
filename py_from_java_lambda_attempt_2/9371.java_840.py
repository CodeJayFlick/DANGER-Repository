Here is a translation of the Java code into equivalent Python code:

```Python
import tkinter as tk
from tkinter import scrolledtext
from datetime import date

class ErrLogDialog:
    def __init__(self):
        self.text_rows = 20
        self.text_columns = 80
        self.send_button_text = "Log Error..."
        self.detail_button_text = "Details >>>"
        self.close_button_text = "<<< Close"

        self.error_id = 0

        # state-dependent gui members
        self.details_panel = None
        self.send_button = None
        self.detail_button = None
        self.main_panel = None
        self.base_title = ""

    def create_exception_dialog(self, title, message, t):
        return ErrLogDialog(title, message, t)

    def __init__(self, title, message, throwable):
        super().__init__()

        if not title:
            base_title = "Error"
        else:
            base_title = title

        error_entry = ErrorEntry(message, throwable)
        self.errors.append(error_entry)

        set_remember_size(False)
        set_remember_location(False)
        build_main_panel(message)

    def add_useful_reporting_info(self, details):
        sb = StringBuilder(details)
        sb.append("\n")
        sb.append("---------------------------------------------------\n")
        sb.append("Build Date: ")
        sb.append(Application.get_build_date())
        sb.append("\n")
        sb.append(Application.get_name())
        sb.append(" Version: ")
        sb.append(Application.get_application_version())
        sb.append("\n")
        sb.append("Java Home: ")
        sb.append(System.getProperty("java.home"))
        sb.append("\n")
        sb.append("JVM Version: ")
        sb.append(System.getProperty("java.vendor"))
        sb.append("  ")
        sb.append(System.getProperty("java.version"))
        sb.append("\n")
        sb.append("OS: ")
        sb.append(System.getProperty("os.name"))
        sb.append("  ")
        sb.append(System.getProperty("os.version"))
        sb.append("  ")
        sb.append(System.getProperty("os.arch"))
        sb.append("\n")
        sb.append("Workstation: <unknown>\n")

    def get_hostname(self):
        hostname = "<unknown>"
        try:
            addr = InetAddress.getLocalHost()
            hostname = addr.getCanonicalHostName()
        except UnknownHostException:
            pass
        return hostname

    @staticmethod
    def set_error_reporter(error_reporter):
        ErrLogDialog.error_reporter = error_reporter

    @staticmethod
    def get_error_reporter():
        return ErrLogDialog.error_reporter

    def build_main_panel(self, message):
        intro_panel = tk.Frame()
        intro_panel.pack(fill="both", expand=True)

        label_icon = tk.Label(intro_panel)
        label_icon.pack(side=tk.LEFT)

        html_message = HTMLUtilities.to_html(message)
        label_text = scrolledtext.ScrolledText(intro_panel, width=300, height=self.text_rows)
        label_text.insert("1.0", html_message + "\n")
        label_text.config(state="disabled")

    def send_details(self):
        details = self.details_panel.get_details()
        close()
        error_reporter.report(root_panel, base_title, details)

    def show_details(self, visible):
        is_showing_details = visible
        if not is_showing_details:
            detail_button_text = "Details >>>"
        else:
            detail_button_text = "<<< Close"

        self.detail_button.config(text=detail_button_text)
        self.details_panel.set_visible(is_showing_details)

    def get_message(self):
        return self.details_panel.get_message()

class ErrorEntry:
    def __init__(self, message, throwable):
        self.message = message
        if throwable is not None:
            details = ReflectionUtilities.stack_trace_to_string(throwable)
        else:
            details = ""
        self.timestamp = date.today()
        self.id = 0

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        if not isinstance(value, int):
            raise ValueError("ErrorEntry ID must be an integer")
        self._id = value

class ErrEntryTableModel:
    def __init__(self):
        super().__init__()

    def create_table_column_descriptor(self):
        descriptor = TableColumnDescriptor()
        descriptor.add_visible_column(IdColumn(), 1, True)
        descriptor.add_visible_column(MessageColumn())
        descriptor.add_hidden_column(DetailsColumn())
        descriptor.add_visible_column(TimestampColumn())

class ErrorDetailsPanel:
    def __init__(self):
        self.text_details = scrolledtext.ScrolledText(root_panel, width=80, height=self.text_rows)

    def set_error(self, error_entry):
        if not isinstance(error_entry, ErrorEntry):
            raise ValueError("ErrorEntry must be an instance of ErrorEntry")
        text = add_useful_reporting_info(error_entry.get_message())
        self.text_details.insert("1.0", text)
```

Note that this translation is based on the assumption that you want to use Tkinter for your GUI in Python, which is a very different approach from Java's Swing library.