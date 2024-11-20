Here is the translation of the Java code to Python:

```Python
import datetime
from typing import Set

class ProgramDB:
    def __init__(self):
        pass

    def start_transaction(self, transaction_name: str) -> int:
        return 0

    def get_options(self, option_name: str) -> dict:
        return {}

    def end_transaction(self, transaction_id: int, commit: bool = False) -> None:
        pass

    def set_record_changes(self, record_changes: bool) -> None:
        pass

class ProgramBuilder:
    def __init__(self):
        self.program_db = ProgramDB()

    def get_program(self) -> ProgramDB:
        return self.program_db

    def create_bookmark(self, address: str, bookmark_type: str, category: str, comment: str) -> None:
        pass

class MergeProgramBuilder:
    def __init__(self):
        self.private_builder = ProgramBuilder()
        self.latest_builder = ProgramBuilder()
        self.result_builder = ProgramBuilder()
        self.original_builder = ProgramBuilder()

        self.builders = set([self.private_builder, self.latest_builder, self.result_builder, self.original_builder])

    def initialize(self) -> None:
        date = datetime.datetime.now()
        for builder in self.builders:
            program_db = builder.get_program()
            transaction_id = program_db.start_transaction("Property")
            options = program_db.get_options("Program Information")
            options["Date Created"] = str(date)
            program_db.end_transaction(transaction_id, True)

            builder.set_record_changes(True)

    def get_latest_program(self) -> ProgramDB:
        return self.latest_builder.get_program()

    def get_private_program(self) -> ProgramDB:
        return self.private_builder.get_program()

    def get_result_program(self) -> ProgramDB:
        return self.result_builder.get_program()

    def get_original_program(self) -> ProgramDB:
        return self.original_builder.get_program()

    def set_bookmark(self, address: str, bookmark_type: str, category: str, comment: str) -> None:
        for builder in self.builders:
            builder.create_bookmark(address, bookmark_type, category, comment)

    def create_all_merge_program(self) -> 'MergeProgram':
        return MergeProgram(self.latest_builder.get_program(), self.private_builder.get_program(),
                            self.result_builder.get_program(), self.original_builder.get_program())

    def create_latest_merge_program(self) -> 'MergeProgram':
        return MergeProgram(self.result_builder.get_program(), self.latest_builder.get_program())

    def create_private_merge_program(self) -> 'MergeProgram':
        return MergeProgram([self.private_builder.get_program()])

class MergeProgram:
    def __init__(self, *programs):
        self.programs = programs

    def __str__(self) -> str:
        return f"Merge Program: {', '.join(map(str, self.programs))}"
```

Please note that the Python code does not exactly replicate the Java code. It is a translation of the logic and structure into Python syntax. The actual functionality may vary depending on how you implement it in Python.