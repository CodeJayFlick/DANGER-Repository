class CompilerSpecNotFoundException(Exception):
    def __init__(self, language_id: str, compiler_spec_id: str) -> None:
        super().__init__(f"Compiler Spec not found for '{language_id}/{compiler_spec_id}'")

    def __init__(self, language_id: str, compiler_spec_id: str, resource_file_name: str, e: Exception) -> None:
        super().__init__(f"Exception reading {language_id}/{compiler_spec_id}({resource_file_name}): {e}")
