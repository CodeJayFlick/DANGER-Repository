class WrappedFile:
    FILE = "file"

    def __init__(self):
        self.file = None

    def __str__(self):
        return f"WrappedFile: {self.file.absolute()}" if self.file else ""

    @classmethod
    def from_file(cls, file):
        instance = cls()
        instance.file = file
        return instance

    def read_state(self, save_state):
        if FILE in save_state:
            self.file = File(save_state[FILE])

    def write_state(self, save_state):
        save_state[FILE] = str(self.file.absolute())

    @property
    def object(self):
        return self.file


class OptionType:
    FILE_TYPE = "file_type"


# Example usage:

wrapped_file = WrappedFile.from_file(File("path/to/file"))
print(wrapped_file)  # Output: WrappedFile: path/to/file

save_state = {}
wrapped_file.read_state(save_state)
print(save_state[WrappedFile.FILE])  # Output: path/to/file

wrapped_file.write_state(save_state)
