import os

class RemoveFileOperator:
    def __init__(self, file):
        self.file = file
        super().__init__()

    @property
    def file(self):
        return self._file

    @file.setter
    def file(self, value):
        self._file = value

    def generate_physical_plan(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

class OperateFilePlan(str):
    pass

# Example usage:

if __name__ == "__main__":
    file_path = "path/to/file.txt"
    operator = RemoveFileOperator(file_path)
    physical_plan = operator.generate_physical_plan()
    print(physical_plan)  # Output: OperateFilePlan("path/to/file.txt", OperatorType.REMOVE_FILE)
