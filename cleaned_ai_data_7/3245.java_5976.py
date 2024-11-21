class AddExternalNameCmd:
    def __init__(self, name: str, source: str):
        self.name = name
        self.source = source
        if not name or len(name) == 0:
            raise ValueError("name is invalid: " + name)

    def apply_to(self, obj):
        program = Program(obj)
        try:
            program.get_external_manager().add_external_library_name(self.name, self.source)
            return True
        except DuplicateNameException as e:
            self.status = f"{self.name} already exists"
        except InvalidInputException as e:
            self.status = str(e)
        return False

    def get_status_msg(self):
        return self.status

    def get_name(self):
        return "Add External Program Name"


class DomainObject:
    pass


class Program(DomainObject):
    def __init__(self, obj=None):
        if not isinstance(obj, DomainObject):
            raise ValueError("obj must be a DomainObject")
        self.obj = obj

    @property
    def get_external_manager(self):
        return ExternalManager()


class SourceType:
    pass


class DuplicateNameException(Exception):
    pass


class InvalidInputException(Exception):
    pass


class ExternalManager:
    def add_external_library_name(self, name: str, source: str) -> None:
        raise NotImplementedError("This method is not implemented")
