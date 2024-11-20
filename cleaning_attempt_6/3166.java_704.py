class SetEquateCmd:
    def __init__(self, equate_name: str, addr: int, op_index: int, equate_value: int):
        self.equate_name = equate_name
        self.addr = addr
        self.op_index = op_index
        self.equate_value = equate_value

    @property
    def name(self) -> str:
        return "Set Equate"

    def apply_to(self, obj: dict) -> bool:
        program = Program(obj)
        equate_table = program.get_equate_table()
        equate = equate_table.get_equate(equate_name)

        if exists_with_different_value(equate):
            self.msg = f"Equate named {equate_name} already exists with value of {equate.value}."
            return False

        if equate is None:
            try:
                equate = equate_table.create_equate(equate_name, equate_value)
            except DuplicateNameException as e:
                self.msg = f"Equate named {equate_name} already exists."
                return False
            except InvalidInputException as e:
                self.msg = f"Invalid equate name: {equate_name}"
                return False

        # Add reference to existing equate
        equate.add_reference(addr, op_index)
        return True

    def get_equate(self) -> dict:
        return {"name": self.equate_name, "value": self.equate_value}

    @property
    def status_msg(self) -> str:
        return self.msg


def exists_with_different_value(equate: dict) -> bool:
    if equate is not None and equate["value"] != equate_value:
        return True

    return False


class Program(dict):
    pass


class EquateTable(dict):
    def get_equate(self, name: str) -> dict:
        # TO DO: implement this method
        pass

    def create_equate(self, name: str, value: int) -> dict:
        # TO DO: implement this method
        pass
