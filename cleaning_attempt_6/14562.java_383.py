class App:
    ERROR = "Error"
    MESSAGE = "Message"

    file_logger_module = None
    console_logger_module = None

    def prepare(self):
        try:
            self.file_logger_module = FileLoggerModule().prepare()
            self.console_logger_module = ConsoleLoggerModule().prepare()
        except FileNotFoundError as e:
            print(f"File not found: {e}")

    def unprepare(self):
        if self.file_logger_module is not None:
            self.file_logger_module.unprepare()
        if self.console_logger_module is not None:
            self.console_logger_module.unprepare()

    def execute(self):
        if self.file_logger_module is not None:
            self.file_logger_module.print_string(App.MESSAGE)
            self.file_logger_module.print_error_string(App.ERROR)

        if self.console_logger_module is not None:
            self.console_logger_module.print_string(App.MESSAGE)
            self.console_logger_module.print_error_string(App.ERROR)


def main():
    app = App()
    try:
        app.prepare()
        app.execute()
        app.unprepare()
    except FileNotFoundError as e:
        print(f"File not found: {e}")


if __name__ == "__main__":
    main()

