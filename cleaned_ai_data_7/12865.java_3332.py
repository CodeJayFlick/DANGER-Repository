class CompilerConstraint:
    def __init__(self):
        self.compiler_id = None

    def is_satisfied(self, program: 'Program') -> bool:
        return str(program.get_compiler_spec().get_compiler_spec_id()) == str(self.compiler_id)

    def load_constraint_data(self, data: dict) -> None:
        self.compiler_id = data['id']

    def __eq__(self, other):
        if not isinstance(other, CompilerConstraint):
            return False
        return str(other.compiler_id) == str(self.compiler_id)

    def get_description(self) -> str:
        return f"compiler = {self.compiler_id}"
