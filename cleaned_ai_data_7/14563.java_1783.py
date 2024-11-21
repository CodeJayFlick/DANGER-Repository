import logging

class ConsoleLoggerModule:
    _singleton = None

    def __init__(self):
        pass

    @classmethod
    def get_singleton(cls):
        if cls._singleton is None:
            cls._singleton = ConsoleLoggerModule()
        return cls._singleton

    def prepare(self):
        self.output = sys.stdout
        self.error = sys.stderr
        logging.debug("ConsoleLoggerModule::prepare();")

    def unprepare(self):
        if self.output:
            self.output.flush()
            self.output.close()

        if self.error:
            self.error.flush()
            self.error.close()
        logging.debug("ConsoleLoggerModule::unprepare();")

    def print_string(self, value: str) -> None:
        self.output.write(value + "\n")
        self.output.flush()

    def print_error_string(self, value: str) -> None:
        self.error.write(value + "\n")
        self.error.flush()
