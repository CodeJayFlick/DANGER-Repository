Here is the translation of the Java code to Python:

```Python
class BatchSegregatingCriteria:
    def __init__(self, loader, load_specs, provider):
        self.group_load_specs = set()
        for load_spec in load_specs:
            self.group_load_specs.add(BatchGroupLoadSpec(load_spec))
        self.loader = loader.name
        self.file_ext = FilenameUtils.get_extension(loader.preferred_file_name(provider))

    @property
    def file_ext(self):
        return self._file_ext

    @file_ext.setter
    def file_ext(self, value):
        self._file_ext = value

    @property
    def loader(self):
        return self._loader

    @loader.setter
    def loader(self, value):
        self._loader = value

    def get_batch_group_load_specs(self):
        result = list(self.group_load_specs)
        result.sort()
        return result

    def get_first_preferred_load_spec(self):
        for group_load_spec in self.group_load_specs:
            if group_load_spec.preferred:
                return group_load_spec
        return None

    def __str__(self):
        return f"[ext: {self.file_ext}, loader: {self.loader}, load specs: {', '.join(map(str, self.group_load_specs))}]"

    def __eq__(self, other):
        if not isinstance(other, BatchSegregatingCriteria):
            return False
        if self._file_ext != other._file_ext:
            return False
        if self._loader != other._loader:
            return False
        if set(self.group_load_specs) != set(other.group_load_specs):
            return False
        return True

    def __hash__(self):
        prime = 31
        result = 1
        result = prime * result + (self.file_ext or "").__hash__()
        result = prime * result + self._loader.__hash__()
        if self.group_load_specs:
            result = prime * result + self.group_load_specs.__hash__()
        return result


class BatchGroupLoadSpec:
    def __init__(self, load_spec):
        self.load_spec = load_spec
        self.preferred = load_spec.is_preferred()

    @property
    def preferred(self):
        return self._preferred

    @preferred.setter
    def preferred(self, value):
        self._preferred = value


from fileinspector import FilenameUtils  # Assuming this is the equivalent of org.apache.commons.io.FilenameUtils in Java
```

Note that I have not translated all parts of the code. For example, `ByteProvider` and `LoadSpec` are not present in Python's standard library, so you would need to implement them yourself or use a third-party library if they exist.