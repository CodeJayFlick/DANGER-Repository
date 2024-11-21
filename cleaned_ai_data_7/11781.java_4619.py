class SleighCompilePreprocessorDefinitionsAdapter:
    def __init__(self, sleigh_compile):
        self.sleigh_compile = sleigh_compile

    def lookup(self, key: str) -> tuple[bool, str]:
        return self.sleigh_compile.get_preproc_value(key)

    def set(self, key: str, value: str) -> None:
        self.sleigh_compile.set_preproc_value(key, value)

    def undefine(self, key: str) -> None:
        self.sleigh_compile.undefine_preproc_value(key)
