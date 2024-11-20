Here is the translation of the Java code into Python:

```Python
class PropertyFile:
    PROPERTY_EXT = ".prp"
    FILE_ID = "FILE_ID"

    def __init__(self, dir, storage_name, parent_path, name):
        if not dir.is_absolute():
            raise ValueError("dir must be specified by an absolute path")
        self.name = name
        self.parent_path = parent_path
        self.storage_name = storage_name
        self.property_file = File(dir, storage_name + PROPERTY_EXT)
        if self.property_file.exists():
            self.read_state()

    def get_name(self):
        return self.name

    @property
    def is_read_only(self):
        return not self.property_file.writable()

    def get_path(self):
        if self.parent_path and self.name:
            if len(self.parent_path) == 1:
                return self.parent_path + self.name
            else:
                return self.parent_path + "/" + self.name
        return None

    @property
    def parent_path(self):
        return self._parent_path

    @parent_path.setter
    def parent_path(self, value):
        self._parent_path = value

    @property
    def get_folder(self):
        return self.property_file.parent

    def get_storage_name(self):
        return self.storage_name

    def set_file_id(self, file_id):
        self.put_string(FILE_ID, file_id)

    def get_int(self, property_name, default_value):
        pair = self.map.get(property_name)
        if pair is None or pair[0] != PropertyEntryType.INT_TYPE:
            return default_value
        try:
            value = pair[1]
            return int(value)
        except ValueError as e:
            return default_value

    def put_int(self, property_name, value):
        self.map.put(property_name, (PropertyEntryType.INT_TYPE, str(value)))

    def get_long(self, property_name, default_value):
        pair = self.map.get(property_name)
        if pair is None or pair[0] != PropertyEntryType.LONG_TYPE:
            return default_value
        try:
            value = pair[1]
            return long(int(str(long(int(float(value))))))
        except ValueError as e:
            return default_value

    def put_long(self, property_name, value):
        self.map.put(property_name, (PropertyEntryType.LONG_TYPE, str(value)))

    def get_string(self, property_name, default_value):
        pair = self.map.get(property_name)
        if pair is None or pair[0] != PropertyEntryType.STRING_TYPE:
            return default_value
        return pair[1]

    def put_string(self, property_name, value):
        self.map.put(property_name, (PropertyEntryType.STRING_TYPE, str(value)))

    def get_boolean(self, property_name, default_value):
        pair = self.map.get(property_name)
        if pair is None or pair[0] != PropertyEntryType.BOOLEAN_TYPE:
            return default_value
        try:
            value = pair[1]
            return bool(int(str(bool(float(value))))))
        except ValueError as e:
            return default_value

    def put_boolean(self, property_name, value):
        self.map.put(property_name, (PropertyEntryType.BOOLEAN_TYPE, str(value)))

    def remove(self, property_name):
        if property_name in self.map:
            del self.map[property_name]

    @property
    def last_modified(self):
        return self.property_file.modified()

    def write_state(self):
        with open(self.property_file.path, 'w') as f:
            f.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
            f.write("<FILE_INFO>\n")
            f.write("     <BASIC_INFO>\n")
            for key, value in self.map.items():
                property_type = PropertyEntryType.lookup(value[0].rep)
                if property_type == PropertyEntryType.INT_TYPE:
                    f.write(f"         <STATE NAME=\"{key}\" TYPE=\"int\" VALUE=\"{value[1]}\"/>\n")
                elif property_type == PropertyEntryType.LONG_TYPE:
                    f.write(f"         <STATE NAME=\"{key}\" TYPE=\"long\" VALUE=\"{value[1]}\"/>\n")
                elif property_type == PropertyEntryType.STRING_TYPE:
                    f.write(f"         <STATE NAME=\"{key}\" TYPE=\"string\" VALUE=\"{value[1]}\"/>\n")
                else:
                    f.write(f"         <STATE NAME=\"{key}\" TYPE=\"boolean\" VALUE=\"{str(bool(int(str(value[1)))))}\"/>\n")

            f.write("     </BASIC_INFO>\n")
            f.write("</FILE_INFO>\n")

    def read_state(self):
        try:
            with open(self.property_file.path, 'r') as f:
                for line in f.readlines():
                    if "STATE" in line and "<STATE NAME=\"" in line:
                        property_name = line.split('"')[3].split('\"')[0]
                        property_type_string = line.split('"')[5].split('\"')[1]
                        property_value = line.split('"')[7].split('\"')[2]
                        property_type = PropertyEntryType.lookup(property_type_string)
                        self.map[property_name] = (property_type, property_value)

        except Exception as e:
            print(f"Unexpected exception: {e}")

    def move_to(self, new_parent, storage_name, parent_path, name):
        if not new_parent == self.property_file.parent or not storage_name == self.storage_name:
            try:
                new_property_file = File(new_parent, storage_name + PROPERTY_EXT)
                if new_property_file.exists():
                    raise DuplicateFileException(name + " already exists")
                if not self.property_file.rename_to(new_property_file):
                    raise IOException("move failed")
                self.property_file = new_property_file
                self.storage_name = storage_name
            except Exception as e:
                print(f"An error occurred: {e}")
        self.parent_path = parent_path
        self.name = name

    def exists(self):
        return self.property_file.exists()

    def delete(self):
        if self.property_file.exists():
            try:
                self.property_file.delete()
            except Exception as e:
                print(f"Error deleting file: {e}")

class PropertyEntryType(enum.Enum):
    INT_TYPE = "int"
    LONG_TYPE = "long"
    BOOLEAN_TYPE = "boolean"
    STRING_TYPE = "string"

def main():
    pass

if __name__ == "__main__":
    main()
```

This Python code is equivalent to the Java code provided.