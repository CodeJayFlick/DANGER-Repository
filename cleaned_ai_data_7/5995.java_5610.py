class DomainFileSizeProjectDataColumn:
    def __init__(self):
        pass

    def get_column_name(self):
        return "Size"

    def get_value(self, info: dict, settings: object, data: object, services: object) -> int | None:
        size_string = info.get("# of Bytes")
        if size_string is None:
            return None
        try:
            return int(size_string)
        except ValueError:
            return None

    def get_column_preferred_width(self):
        return 120

    def is_default_column(self):
        return True

    def get_priority(self):
        return 5


# Example usage:

domain_file_info = {"# of Bytes": "123"}
settings = object()
data = object()
services = object()

column = DomainFileSizeProjectDataColumn()
print(column.get_value(domain_file_info, settings, data, services))  # Output: 123
