import collections

class ElfExtensionFactory:
    @classmethod
    def get_all_extensions(cls):
        return [cls._get_extension_instance() for _ in range(len(ElfExtension.__subclasses__()))]

    @classmethod
    def get_load_adapter(cls, elf_header: 'ElfHeader') -> 'ElfLoadAdapter':
        for handler in ElfExtensionFactory.get_all_extensions():
            if handler.can_handle(elf_header):
                return handler
        return None

class ElfExtension:
    pass

class ElfLoadAdapter:
    pass

class ElfHeader:
    pass
