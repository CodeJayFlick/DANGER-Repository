class OriginalProgramModifierListener:
    def modify_original(self, program: 'ghidra.program.database.ProgramDB') -> None:
        raise NotImplementedError
