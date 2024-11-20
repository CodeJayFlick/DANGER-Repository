import tkinter as tk
from tkinter import messagebox
import re

class DockingErrorDisplay:
    def __init__(self):
        self.active_dialog = None
        self.console_display = ConsoleErrorDisplay()

    def display_info_message(self, error_logger, originator, parent, title, message):
        self.display_message(MessageType.INFO, error_logger, originator, parent, title, message)

    def display_error_message(self, error_logger, originator, parent, title, message, throwable):
        self.display_message(MessageType.ERROR, error_logger, originator, parent, title, message, throwable)

    def display_warning_message(self, error_logger, originator, parent, title, message, throwable):
        self.display_message(MessageType.WARNING, error_logger, originator, parent, title, message, throwable)

    class MessageType:
        INFO = 0
        WARNING = 1
        ERROR = 2

    def wrap(self, text):
        lines = re.split(r'(\n)', text)
        wrapped_text = ''
        for line in lines[1:]:
            if len(wrapped_text) > 120 and not self.is_blank(line.strip()):
                wrapped_text += '\n'
            wrapped_text += line
        return wrapped_text

    def display_message(self, message_type, error_logger, originator, parent, title, message):
        dialog_type = OptionDialog.PLAIN_MESSAGE
        if message:
            safe_message = re.sub(r'[^ -~]+', '', str(message))
            if len(safe_message) > 1000:
                safe_message = self.wrap(safe_message)
            unformatted_message = HTMLUtilities.from_html(safe_message)

        switch (message_type):
            case MessageType.INFO:
                dialog_type = OptionDialog.INFORMATION_MESSAGE
                self.console_display.display_info_message(error_logger, originator, parent, title, unformatted_message)
                break

            case MessageType.WARNING | MessageType.ALERT:
                dialog_type = OptionDialog.WARNING_MESSAGE
                self.console_display.display_warning_message(error_logger, originator, parent, title, unformatted_message, None)

            case MessageType.ERROR:
                self.console_display.display_error_message(error_logger, originator, parent, title, unformatted_message, None)
                break

        show_dialog(title, None, dialog_type, message, get_window(parent))

    def get_window(self, component):
        while component and not isinstance(component, tk.Toplevel):
            component = component.master
        return component

    def show_dialog(self, title, throwable, dialog_type, message_string, parent):
        if dialog_type == OptionDialog.ERROR_MESSAGE:
            self.show_dialog_on_swing(title, throwable, dialog_type, message_string, parent)
        else:
            DockingWindowManager.show_dialog(parent, OkDialog(title, message_string, dialog_type))

    def show_dialog_on_swing(self, title, throwable, dialog_type, message_string, parent):
        if self.active_dialog is not None:
            self.active_dialog.add_exception(message_string, throwable)
            return

        self.active_dialog = create_error_dialog(title, throwable, message_string)

        self.active_dialog.set_closed_callback(lambda: (self.active_dialog.set_closed_callback(None), self.active_dialog = None))
        DockingWindowManager.show_dialog(parent, self.active_dialog)

    def create_error_dialog(self, title, throwable, message_string):
        if contains_multiple_causes(throwable):
            return ErrLogExpandableDialog(title, message_string, throwable)
        else:
            return ErrLogDialog.create_exception_dialog(title, message_string, throwable)

    def is_blank(self, line):
        return re.match(r'^\s*$', line) is not None

    def contains_multiple_causes(throwable):
        if throwable is None:
            return False
        if isinstance(throwable, MultipleCauses):
            return True
        return contains_multiple_causes(throwable.getCause())

class ConsoleErrorDisplay:

    def display_info_message(self, error_logger, originator, parent, title, message):
        pass

    def display_warning_message(self, error_logger, originator, parent, title, message, throwable):
        pass

    def display_error_message(self, error_logger, originator, parent, title, message, throwable):
        pass
