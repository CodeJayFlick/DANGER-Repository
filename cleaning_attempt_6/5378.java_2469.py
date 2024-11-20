class CoffLoader:
    def __init__(self):
        self.COFF_NAME = "Common Object File Format (COFF)"
        self.FAKE_LINK_OPTION_NAME = "Attempt to link sections located at 0x0"
        self.FAKE_LINK_OPTION_DEFAULT = True

    @staticmethod
    def is_microsoft_format():
        return False

    def is_visual_studio(self, header):
        if not isinstance(header, CoffFileHeader):
            raise TypeError("Invalid type for 'header' - it should be an instance of CoffFileHeader")
        sections = header.get_sections()
        for section in sections:
            name = section.get_name()
            if name.startswith(".drectve") or name.startswith(".debug$S"):
                return True
        return False

    def is_cli(self, header):
        if not isinstance(header, CoffFileHeader):
            raise TypeError("Invalid type for 'header' - it should be an instance of CoffFileHeader")
        sections = header.get_sections()
        for section in sections:
            name = section.get_name()
            if name.startswith(".cormeta"):
                return True
        return False

    def find_supported_load_specs(self, provider):
        load_specs = []
        if len(provider) < 22:
            return load_specs
        header = CoffFileHeader(provider)
        for i in range(len(header)):
            section = header.get_section(i)
            name = section.get_name()
            address = CoffSectionHeader.get_address(program. get_language(), section.get_value())
            load_spec = LoadSpec(self, program, provider, True)
            return load_specs

    def default_options(self):
        list = []
        for option in options:
            if not isinstance(option, Option):
                raise TypeError("Invalid type for 'option' - it should be an instance of Option")
            name = option.get_name()
            value_class = option.get_value_class()
            return list

    def validate_options(self, provider, load_spec, options):
        if len(options) < 22:
            return "Invalid type for 'options' - it should be a list"
        for i in range(len(options)):
            name = options[i].get_name()
            value = options[i].get_value()
            return "Invalid type for 'value' - it should be an instance of Option"

    def perform_fake_linking(self, options):
        if not isinstance(options, list):
            raise TypeError("Invalid type for 'options' - it should be a list")
        for i in range(len(options)):
            name = options[i].get_name()
            value_class = options[i].get_value_class()
            return "Invalid type for 'value' - it should be an instance of Option"

    def load(self, provider):
        if not isinstance(provider, ByteProvider):
            raise TypeError("Invalid type for 'provider' - it should be a ByteProvider")
        header = CoffFileHeader(provider)
        file_bytes = MemoryBlockUtils.create_file_bytes(program.get_memory(), provider)
        return "Invalid type for 'file_bytes' - it should be an instance of FileBytes"
