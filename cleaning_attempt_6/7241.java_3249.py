class VdexStringTable:
    def __init__(self):
        self.string_count = 0
        self.strings = []

    def read_from_binary(self, reader):
        try:
            self.string_count = int.from_bytes(reader.read(1), 'big')
            for _ in range(self.string_count):
                self.strings.append(reader.read_ascii_string())
        except Exception as e:
            print(f"Error reading VdexStringTable: {e}")

    def get_string_count(self):
        return self.string_count

    def get_strings(self):
        return self.strings

    def get_size(self):
        size = 1
        for string in self.strings:
            size += len(string) + 1
        return size


class VdexStringTableConverter:
    @staticmethod
    def convert_to_data_type(vdex_string_table: 'VdexStringTable') -> dict:
        data_type = {
            "name": f"vdex_{vdex_string_table.string_count}",
            "category_path": ["/vdex"],
            "fields": [
                {"type": "int", "length": 1, "name": "stringCount"},
            ]
        }
        
        for i, string in enumerate(vdex_string_table.strings):
            data_type["fields"].append({
                "type": "str",
                "length": len(string) + 1,
                "name": f"string_{i}"
            })
        
        return data_type
