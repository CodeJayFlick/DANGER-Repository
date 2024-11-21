Here is the translation of the Java code into Python:

```Python
class FileSelectorStub:
    def __init__(self):
        self.opened = False
        self.presenter = None
        self.name = ""
        self.num_of_message_sent = 0
        self.data_displayed = False

    def open(self):
        self.opened = True

    def set_presenter(self, presenter):
        self.presenter = presenter

    def is_opened(self):
        return self.opened

    def get_presenter(self):
        return self.presenter

    def get_file_name(self):
        return self.name

    def set_file_name(self, name):
        self.name = name

    def show_message(self, message):
        self.num_of_message_sent += 1

    def close(self):
        self.opened = False

    def display_data(self, data):
        self.data_displayed = True

    def get_messages_sent(self):
        return self.num_of_message_sent

    def data_displayed(self):
        return self.data_displayed
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation.