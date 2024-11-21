class ContextEvaluatorAdapter:
    def evaluate_context_before(self, context: dict, instruction: str) -> bool:
        return False

    def evaluate_context(self, context: dict, instruction: str) -> bool:
        return False

    def evaluate_constant(self, context: dict, instruction: str, pcodeop: int, constant: int, size: int, ref_type: str) -> int or None:
        return None

    def evaluate_reference(self, context: dict, instruction: str, pcodeop: int, address: int, size: int, ref_type: str) -> bool:
        return False

    def evaluate_destination(self, context: dict, instruction: str) -> bool:
        return False

    def unknown_value(self, context: dict, instruction: str, node: object) -> int or None:
        return None

    def follow_false_conditional_branches(self) -> bool:
        return True

    def evaluate_symbolic_reference(self, context: dict, instruction: str, address: int) -> bool:
        return False

    def allow_access(self, context: dict, addr: int) -> bool:
        return False
