class MissingTOCTargetIDInvalidLink:
    def __init__(self, help: 'help.validator.location.HelpModuleCollection', item: 'help.validator.model.TOCItem'):
        self.help = help
        self.item = item

    def identity_hash(self):
        return hash(self.item)

    @property
    def source_file(self):
        return self.item.source_file

    @property
    def line_number(self):
        return self.item.line_number

    def compare_to(self, other: 'MissingTOCTargetIDInvalidLink'):
        if not isinstance(other, MissingTOCTargetIDInvalidLink):
            return -1  # always put us above other types of Invalid Links

        source_file = self.item.source_file
        other_source_file = other.item.source_file
        result = source_file.compare_to(other_source_file)
        if result != 0:
            return result

        return self.item.id_attribute.compare_to(other.item.id_attribute)

    def __str__(self):
        return f"Missing TOC target ID for definition (<tocdef>):\n\t{self.item}"

    def hash(self):
        prime = 31
        result = 1
        if not self.help:
            result *= 0
        else:
            result *= hash(self.help)
        if not self.item:
            result *= 0
        else:
            result *= hash(self.item)

        return result

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, MissingTOCTargetIDInvalidLink):
            return False

        if not self.help and not other.help:
            pass  # both are None
        elif not self.help or not other.help:  # one of them is None
            return False
        else:
            return hash(self.help) == hash(other.help)

        if not self.item and not other.item:
            pass  # both are None
        elif not self.item or not other.item:  # one of them is None
            return False
        else:
            return hash(self.item) == hash(other.item)

        return True

    def __hash__(self):
        prime = 31
        result = 1
        if not self.help:
            result *= 0
        else:
            result *= hash(self.help)
        if not self.item:
            result *= 0
        else:
            result *= hash(self.item)

        return result

    def __lt__(self, other):
        # implement your own comparison logic here
        pass
