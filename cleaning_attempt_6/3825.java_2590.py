class RenameEquatesCmd:
    def __init__(self, old_equate_name: str, new_equate_name: str):
        self.old_equate_name = old_equate_name
        self.new_equate_name = new_equate_name

    @property
    def name(self) -> str:
        return "Rename Equates"

    def apply_to(self, obj: dict) -> bool:
        program = Program(obj)
        equate_table = program.get_equate_table()

        from_equate = equate_table.get_equate(old_equate_name)

        if not from_equate:
            msg = f"Equate not found: {old_equate_name}"
            return False

        to_equate = equate_table.get_equate(new_equate_name)
        
        if not to_equate:
            try:
                to_equate = equate_table.create_equate(new_equate_name, from_equate.value)
            except (DuplicateNameException, InvalidInputException) as e:
                msg = f"Invalid equate name: {new_equate_name}"
                return False

        ref_list = [ref for ref in from_equate.references]
        
        try:
            equate_table.remove_equate(old_equate_name)
        except Exception as e:
            pass
        
        for element in ref_list:
            to_equate.add_reference(element.address, element.op_index)

        return True

    @property
    def status_msg(self) -> str:
        return self.msg


class Program(dict):
    def get_equate_table(self) -> dict:
        return {"get_equate": lambda name: None,
                "create_equate": lambda name, value: {"name": name, "value": value},
                "remove_equate": lambda name: None}

    @property
    def references(self) -> list:
        return []
