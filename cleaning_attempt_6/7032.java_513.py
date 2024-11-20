class ArtUtilities:
    @staticmethod
    def create_fragment(program: 'Program', fragment_name: str, start_address: int, end_address: int) -> None:
        module = program.get_listing().get_root_module(0)
        if not hasattr(module, 'fragments'):
            module.fragments = {}
        try:
            fragment = ArtUtilities.get_fragment(module, fragment_name)
            if fragment is None:
                fragment = module.create_fragment(fragment_name)
            fragment.move(start_address, end_address - 1)
        except Exception as e:
            print(f"An error occurred: {e}")

    @staticmethod
    def get_fragment(module: 'ProgramModule', fragment_name: str) -> 'ProgramFragment':
        if not hasattr(module, 'fragments'):
            module.fragments = {}
        for group in module.get_children():
            if group.name == fragment_name:
                return group
        return None

    @staticmethod
    def adjust_for_thumb_as_needed(art_header: dict, program: 'Program', address: int) -> int:
        displacement = address % 4
        processor = next((p for p in ['ARM']), None)
        if art_header.get('processor') == processor and (displacement & 1):
            return address - 1
        else:
            return address

class ProgramFragment:
    def move(self, start: int, end: int) -> None:
        pass

class RegisterValue:
    def __init__(self, register: str, value: int) -> None:
        self.register = register
        self.value = value

class ContextChangeException(Exception):
    pass
