class InjectPayloadJumpAssist:
    def __init__(self, base_name: str, source_name: str):
        self.base_name = base_name
        super().__init__(source_name)
        self.type = "EXECUTABLEPCODE_TYPE"

    def restore_xml(self, parser: dict, language: object) -> None:
        subel = next((x for x in parser.values()), None)
        if subel.get("name")[0] == 'c':
            self.name = f"{self.base_name}_index2case"
        elif subel.get("name")[0] == 'a':
            self.name = f"{self.base_name}_index2addr"
        elif subel.get("name")[0] == 's':
            self.name = f"{self.base_name}_calcsize"
        else:
            self.name = f"{self.base_name}_defaultaddr"
        super().restore_xml(parser, language)
