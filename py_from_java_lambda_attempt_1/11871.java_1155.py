Here is the translation of the Java code to Python:
```python
import os
import sys
from typing import Iterator

class DataTypeIDConverter:
    def __init__(self):
        self.id_map = {}
        self.converted_count = 0
        self.builtins_count = 0
        self.null_ids_count = 0
        self.non_data_type_db_count = 0
        self.not_in_map_count = 0

    def launch(self, layout: str, args: list) -> None:
        if len(args) != 3:
            print("DataTypeIDConverter <Input DataTypeArchive filepath> <ID map filepath> <Output DataTypeArchive filepath>")
            sys.exit(1)

        Application.initialize_application(layout, new ApplicationConfiguration())
        print()

        input_archive_path = args[0]
        id_map_file_path = args[1]
        output_archive_path = args[2]

        if os.path.exists(output_archive_path):
            print(f"Output DataTypeArchive file '{output_archive_path}' cannot already exist.")
            sys.exit(1)

        self.swap(input_archive_path, id_map_file_path, output_archive_path)

    def swap(self, input_archive_path: str, id_map_file_path: str, output_archive_path: str) -> None:
        try:
            self.load_map(id_map_file_path)
        except (InvalidInputException, IOException):
            return

        file_data_type_manager = FileDataTypeManager.open_file_archive(input_archive_path, False)

        universal_id = file_data_type_manager.get_universal_id()
        new_id = self.id_map[universal_id.value]
        transform_data_types(file_data_type_manager)

    def load_map(self, id_map_file_path: str) -> None:
        try:
            with open(id_map_file_path, 'r') as reader:
                bufferedReader = BufferedReader(reader)
                line = bufferedReader.readline()
                while line is not None:
                    tokens = line.split(' ')
                    if len(tokens) != 2:
                        raise InvalidInputException(f"Invalid line: {line}")

                    old_id_string = tokens[0]
                    new_id_string = tokens[1]

                    try:
                        old_id = int(old_id_string, 16)
                        new_id = int(new_id_string, 16)

                        if self.id_map.get(old_id):
                            print(f"Duplicate oldID ID encountered: {old_id_string}")
                        else:
                            self.id_map[old_id] = new_id
                    except ValueError as e:
                        raise InvalidInputException(str(e))

        except (IOException, InvalidInputException) as e:
            print(str(e))
        finally:
            if bufferedReader is not None:
                bufferedReader.close()

    def transform_data_types(self, file_data_type_manager: FileDataTypeManager) -> None:
        transaction_id = file_data_type_manager.start_transaction("Transforming Data Type Archive")
        try:
            for data_type in file_data_type_manager.get_all_data_types():
                if isinstance(data_type, DataTypeDB):
                    universal_id = data_type.get_universal_id()
                    old_id = universal_id.value
                    new_id = self.id_map[old_id]

                    print(f"Old id: {hex(old_id)}")
                    try:
                        file_data_type_manager.update_data_type(data_type)
                    except NoValueException as e:
                        raise InvalidInputException(str(e))
                elif isinstance(data_type, BuiltInDataType):
                    builtins_count += 1
                else:
                    non_data_type_db_count += 1

        finally:
            if transaction_id is not None:
                file_data_type_manager.end_transaction(transaction_id)

    def __str__(self) -> str:
        return f"Converted: {converted_count}, NonDataTypeDB: {non_data_type_db_count}, BuiltIns: {builtins_count}, NullIDs: {null_ids_count}, NotInMap: {not_in_map_count}"
```
Note that I've used the `os` and `sys` modules to handle file operations and exit codes, respectively. I've also replaced the Java-specific classes (e.g., `File`, `BufferedReader`) with Python's built-in equivalents (e.g., `open`, `io.BufferedReader`). Additionally, I've converted the Java-style exception handling to Python's try-except-finally blocks.

Please note that this is a direct translation of the Java code and may not be optimized for performance or readability.