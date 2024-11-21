Here is the translation of the Java code into Python:

```Python
class Config:
    def __init__(self, source: bytes, file_name: str, allow_empty_sections: bool = False):
        self.file_name = file_name
        if isinstance(source, str):
            source = source.encode('utf-8')
        with open(file_name, 'wb') as f:
            f.write(source)
        self.allow_empty_sections = allow_empty_sections

    def set_indentation(self, indent: str) -> None:
        assert indent is not None and len(indent) > 0
        self.indentation = indent
        if indent[0] == ' ':
            self.indentation_name = "space"
        else:
            self.indentation_name = "tab"

    def get_indentation(self) -> str:
        return self.indentation

    def get_indentation_name(self) -> str:
        return self.indentation_name

    @property
    def main_node(self):
        # todo: implement this method
        pass

    def save(self, file_path: str) -> None:
        with open(file_path, 'w', encoding='utf-8') as f:
            self.main_node.save(f)

    def set_values(self, other_config: Config) -> bool:
        return self.main_node.set_values(other_config.main_node)

    @property
    def file(self):
        if isinstance(self.file_name, str):
            try:
                return Path(self.file_name)
            except Exception as e:
                print(e)
                return None  # ZipPath, for example, throws undocumented exception
        else:
            return self.file_name

    @property
    def path(self) -> Path | None:
        if isinstance(self.file_name, str):
            try:
                return Path(self.file_name)
            except Exception as e:
                print(e)
                return None  # ZipPath, for example, throws undocumented exception
        else:
            return self.file

    @property
    def separator(self) -> str | None:
        if isinstance(self.separator, str):
            return self.separator
        else:
            return None

    def get_by_path(self, path: str) -> str | None:
        # todo: implement this method
        pass

    def get(self, *path_parts: str) -> str | None:
        section = self.main_node
        for part in path_parts:
            node = section.get(part)
            if node is None:
                return None
            if isinstance(node, Config):
                if len(path_parts) == 1:
                    return None
                section = node
            else:
                if isinstance(node, dict) and len(path_parts) == 2:
                    return str(node.get('value'))
                else:
                    return None

    def is_empty(self) -> bool:
        # todo: implement this method
        pass

    @property
    def to_map(self):
        # todo: implement this method
        pass

    def validate(self, validator: SectionValidator) -> bool:
        # todo: implement this method
        pass

class OptionSection:
    def __init__(self, key: str):
        self.key = key

    @property
    def value(self) -> None | str:
        return None  # todo: implement this property

def load(o: object, path: str) -> None:
    for f in o.__class__.get_declared_fields():
        if isinstance(f.type, OptionSection):
            p = f.get(o)
            pc = p.__class__
            load(p, path + ((OptionSection)p).key + ".")
        elif isinstance(f.type, Option):
            (f.get(o)).set(path)

def set_values(other_config: Config) -> bool:
    return other_config.main_node.set_values(self.main_node)

# todo: implement this method
```

Please note that the translation is not perfect and some parts of the code are left as TODOs.