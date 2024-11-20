class GhidraScriptProperties:
    def __init__(self):
        self.properties_map = {}
        self.base_name = None

    def load_glidra_script_properties(self, script_location: str, new_base_name: str) -> None:
        if not isinstance(script_location, str):
            raise TypeError("script_location must be a string")
        if not isinstance(new_base_name, str):
            raise TypeError("new_base_name must be a string")

        self.base_name = new_base_name
        prop_file_name = f"{self.base_name}.properties"
        child_files = [file for file in os.listdir(script_location) if os.path.isfile(os.path.join(script_location, file))]
        prop_file = None

        for ch_file in child_files:
            if ch_file == prop_file_name:
                prop_file = os.path.join(script_location, ch_file)
                break
        else:
            Msg.warn(self, f"The path '{script_location}' is not a valid directory.")
            return

        self.load_glidra_script_properties(prop_file)

    def get_filename(self) -> str:
        return f"{self.base_name}.properties"

    @staticmethod
    def load_glidra_script_properties(possible_locations: list, new_base_name: str) -> None:
        for location in possible_locations:
            if not isinstance(location, str):
                raise TypeError("location must be a string")
            if not isinstance(new_base_name, str):
                raise TypeError("new_base_name must be a string")

    def load_glidra_script_properties(self, file_path: str) -> None:
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    equals_index = line.find('=')
                    if equals_index > 0:
                        key = line[:equals_index].strip()
                        value = line[equals_index + 1:].strip()
                        self.properties_map[key] = value
        except FileNotFoundError as e:
            raise IOException("Could not find .properties file '" + file_path + "'") from e

    def put(self, key: str, value: str) -> None:
        return self.properties_map.put(key.strip(), value)

    def get_value(self, key_string: str) -> str:
        if len(self.properties_map) == 0:
            return ""
        if key_string in self.properties_map:
            return self.properties_map[key_string]
        return ""

    @property
    def is_empty(self) -> bool:
        return len(self.properties_map) == 0

    def remove(self, key_string: str) -> None:
        return self.properties_map.pop(key_string)

    def clear_properties(self) -> None:
        self.properties_map.clear()

    def contains_key(self, key_string: str) -> bool:
        return key_string in self.properties_map

    def contains_value(self, value_string: str) -> bool:
        for _, value in self.properties_map.items():
            if value == value_string:
                return True
        return False

    @property
    def keys(self) -> set:
        return self.properties_map.keys()

    def values(self) -> list:
        return list(self.properties_map.values())
