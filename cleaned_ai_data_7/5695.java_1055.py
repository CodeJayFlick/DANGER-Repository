class GFileSystemProgramProvider:
    def get_program(self, file: 'ghidra.GFile', language_service: 'ghidra.LanguageService',
                    monitor: 'ghidra.TaskMonitor', consumer: object) -> 'ghidra.Program':
        # NOTE: ONLY OVERRIDE THIS METHOD IF YOU CANNOT PROVIDE AN INPUT STREAM
        # TO THE INTERNAL FILES OF THIS FILE SYSTEM!
        raise NotImplementedError

    def can_provide_program(self, file: 'ghidra.GFile') -> bool:
        return False  # default implementation returns False
