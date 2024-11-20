Here's a translation of your Java code into equivalent Python:

```Python
class IoTDBResultMetadata:
    def __init__(self,
                 non_align: bool,
                 sg_columns: list[str],
                 operation_type: str,
                 column_info_list: list[str],
                 column_type_list: list[str],
                 ignore_timestamp: bool):
        self.sg_columns = sg_columns
        self.operation_type = operation_type
        self.column_info_list = column_info_list
        self.column_type_list = column_type_list
        self.ignore_timestamp = ignore_timestamp
        self.non_align = non_align

    def is_wrapper_for(self, arg0) -> None:
        raise Exception("Method not supported")

    def unwrap(self, arg0: type[T]) -> T:
        raise Exception("Method not supported")

    def get_catalog_name(self, column: int) -> str | None:
        if self.operation_type == "SHOW":
            return "_system_database"  # or other values based on the operation
        elif self.non_align:
            return self.sg_columns[column - 1]
        else:
            return self.sg_columns[column - 2]

    def get_column_class_name(self, column: int) -> str | None:
        if self.column_type_list is not None and len(self.column_type_list) > 0:
            column_type = self.column_type_list[column - 1].upper()
            if column_type == "TIMESTAMP":
                return "datetime"
            elif column_type in ["BOOLEAN", "INT32", "FLOAT"]:
                return f"{column_type.lower()}64" if column_type != "BOOLEAN" else "bool"
            elif column_type in ["DOUBLE", "TEXT"]:
                return "float" if column_type == "DOUBLE" else "str"

    def get_column_count(self) -> int:
        return len(self.column_info_list)

    def get_column_display_size(self, arg0: int) -> None:
        raise Exception("Method not supported")

    def get_column_label(self, column: int) -> str | None:
        if self.column_info_list is not None and 1 <= column <= len(self.column_info_list):
            return self.column_info_list[column - 1]

    def get_column_name(self, column: int) -> str | None:
        return self.get_column_label(column)

    @staticmethod
    def check_column_index(column: int) -> None:
        if not isinstance(column, int) or column < 0:
            raise Exception("Invalid column index")

    def get_column_type(self, column: int) -> type[T]:
        if self.column_info_list is not None and len(self.column_info_list) > 0:
            return {
                "BOOLEAN": bool,
                "INT32": int,
                "FLOAT": float,
                "DOUBLE": float
            }[self.column_type_list[column - 1].upper()]

    def get_column_type_name(self, column: int) -> str | None:
        if self.column_info_list is not None and len(self.column_info_list) > 0:
            return {
                "BOOLEAN": "boolean",
                "INT32": "int",
                "FLOAT": "float",
                "DOUBLE": "double"
            }[self.column_type_list[column - 1].upper()]

    def get_precision(self, column: int) -> None:
        raise Exception("Method not supported")

    def get_scale(self, column: int) -> None:
        raise Exception("Method not supported")

    def get_schema_name(self, column: int) -> str | None:
        return self.get_catalog_name(column)

    def get_table_name(self, column: int) -> str | None:
        if self.column_info_list is not None and len(self.column_info_list) > 0:
            return {
                "TIME": "time",
                # or other values based on the operation
            }[self.operation_type]

    def is_auto_increment(self, arg0: int) -> bool:
        return False

    def is_case_sensitive(self, arg0: int) -> bool:
        return True

    def is_currency(self, arg0: int) -> bool:
        return False

    def is_definitely_writable(self, arg0: int) -> bool:
        return False

    def is_nullable(self, arg0: int) -> None:
        raise Exception("Method not supported")

    def is_read_only(self, arg0: int) -> bool:
        return True

    def is_searchable(self, arg0: int) -> bool:
        return True

    def is_signed(self, arg0: int) -> bool:
        return True

    def is_writable(self, arg0: int) -> bool:
        return False
```

This Python code defines a class `IoTDBResultMetadata` that mimics the behavior of your Java code. The methods are mostly equivalent to their counterparts in the original Java code.