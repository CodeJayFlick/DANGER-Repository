import logging
from io import StringIO


class HeadlessErrorLogger:
    def __init__(self, log_file=None):
        self.log_writer = None
        if log_file is not None:
            self.set_log_file(log_file)

    def set_log_file(self, log_file):
        try:
            if log_file is None:
                if self.log_writer is not None:
                    message = "File logging disabled"
                    self.write_log("INFO", [message])
                    self.log_writer.close()
                    self.log_writer = None
                return

            writer = open(log_file, 'w')
            if self.log_writer is not None:
                message = f"Switching log file to: {log_file}"
                self.write_log("INFO", [message])
                self.log_writer.close()

            self.log_writer = writer
        except Exception as e:
            print(f"Failed to open log file {log_file}: {e}")

    def write_log(self, level, message):
        if self.log_writer is None:
            return

        for line in message:
            self.log_writer.write(f"{level} {line}\n")
        self.log_writer.flush()

    def write_log_level_text(self, level, text):
        if self.log_writer is None:
            return
        lines = text.split('\n')
        for line in lines:
            self.write_log(level, [line])
        self.log_writer.flush()

    def write_log_level_text throwable(self, level, text, e):
        if self.log_writer is None:
            return

        self.write_log_level_text(level, text)
        for element in e.get_traceback():
            self.write_log(f"{level} {element}", [])

    @property
    def log_file_name(self):
        return self._log_file_name

    @log_file_name.setter
    def set_log_file_name(self, value):
        if not isinstance(value, str):
            raise TypeError("Log file name must be a string")
        self._log_file_name = value


class ErrorLogger:
    def debug(self, originator, message):
        # TODO for some reason debug is off
        pass

    def error(self, originator, message):
        if isinstance(message, str):
            self.write_log("ERROR", [message])
        else:
            raise TypeError("Error messages must be strings")

    def info(self, originator, message):
        if isinstance(message, str):
            self.write_log("INFO", [message])
        else:
            raise TypeError("Info messages must be strings")

    def trace(self, originator, message):
        # TODO for some reason tracing is off
        pass

    def warn(self, originator, message):
        if isinstance(message, str):
            self.write_log("WARN", [message])
        else:
            raise TypeError("Warning messages must be strings")


if __name__ == "__main__":
    error_logger = HeadlessErrorLogger()
