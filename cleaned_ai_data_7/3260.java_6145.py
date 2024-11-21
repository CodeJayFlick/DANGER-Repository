class SetExternalNameCmd:
    def __init__(self, external_name: str, external_path: str):
        self.external_name = external_name
        self.external_path = external_path
        self.status = None
        self.user_defined = True

    def apply_to(self, obj) -> bool:
        if not isinstance(obj, Program):
            return False
        
        try:
            p.get_external_manager().set_external_path(external_name=self.external_name,
                                                        path=self.external_path,
                                                        user_defined=self.user_defined)
        except InvalidInputException as e:
            self.status = "Invalid name specified"
            return False

        return True

    def get_status_msg(self) -> str:
        return self.status

    def get_name(self) -> str:
        return "Set External Program Name"


class Program:
    def __init__(self):
        pass

    def get_external_manager(self):
        # TO DO: implement this method
        raise NotImplementedError


# Example usage:

program = Program()
cmd = SetExternalNameCmd("my_program", "/path/to/my/program")
result = cmd.apply_to(program)
print(cmd.get_status_msg())
