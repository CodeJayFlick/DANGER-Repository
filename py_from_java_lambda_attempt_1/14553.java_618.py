Here is the translation of the Java interface into a Python class:

```Python
class FileSelectorView:
    def __init__(self):
        self.presenter = None
        self.file_name = ""

    def open(self):
        pass  # implement this method in your subclass

    def close(self):
        pass  # implement this method in your subclass

    @property
    def is_opened(self):
        return False  # default value, override if needed

    def set_presenter(self, presenter: 'FileSelectorPresenter'):
        self.presenter = presenter

    @property
    def presenter(self) -> 'FileSelectorPresenter':
        return self.presenter

    def set_file_name(self, name: str):
        self.file_name = name

    @property
    def file_name(self) -> str:
        return self.file_name

    def show_message(self, message: str):
        pass  # implement this method in your subclass

    def display_data(self, data: str):
        pass  # implement this method in your subclass
```

Note that I used the `@property` decorator to create getter and setter methods for the `presenter`, `file_name`, etc. This is a common Python idiom for creating read-only or write-only properties.

Also note that I did not include any serialization logic, as Java's `Serializable` interface does not have an equivalent in Python. If you need to serialize this class, you will need to implement the necessary code using Python's built-in serialization mechanisms (such as JSON or Pickle).