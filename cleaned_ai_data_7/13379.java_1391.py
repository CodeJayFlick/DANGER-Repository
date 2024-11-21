class ElfSH4RelocationFixupHandler:
    def process_relocation(self, program: 'Program', relocation: 'Relocation', old_image_base: int, new_image_base: int) -> bool:
        if relocation.get_type() in [0x6, 0xd, 0xe, 0xf]:
            return self.process_32_bit_relocation(program, relocation, old_image_base, new_image_base)
        return False

    def process_handles_program(self, program: 'Program') -> bool:
        if not isinstance(program.get_executable_format(), str) or "ELF" != program.get_executable_format():
            return False
        language = program.get_language()
        processor = language.get_processor()
        return ("SuperH4" == str(processor)) or ("SuperH" == str(processor))

class Program:
    def __init__(self, executable_format: str):
        self.executable_format = executable_format

class Relocation:
    def get_type(self) -> int:
        pass  # implement this method in your subclass
