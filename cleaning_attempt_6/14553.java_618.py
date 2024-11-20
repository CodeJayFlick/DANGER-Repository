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
