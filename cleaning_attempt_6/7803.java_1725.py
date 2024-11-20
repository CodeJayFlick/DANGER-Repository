class MicrosoftDemangler:
    def __init__(self):
        pass

    def can_demangle(self, program: str) -> bool:
        executable_format = program.get_executable_format()
        return executable_format is not None and (executable_format.find("PE") != -1 or executable_format.find("MSCOFF") != -1)

    @staticmethod
    def demangle_ms(mangled: str, demangle_only_known_patterns: bool) -> dict:
        if mangled is None or len(mangled) == 0:
            raise ValueError("Invalid input")

        try:
            # Create a MDMangGhidra object and call its demangle method
            demangler = MDMangGhidra()
            result = demangler.demangle(mangled, demangle_only_known_patterns)
            return result
        except Exception as e:
            raise ValueError(f"Unable to demangle symbol: {mangled}") from e

    def demangle(self, mangled: str, options: dict) -> dict:
        try:
            if "demangleOnlyKnownPatterns" in options:
                return self.demangle_ms(mangled, options["demangleOnlyKnownPatterns"])
            else:
                raise ValueError("Invalid input")
        except Exception as e:
            raise ValueError(f"Unable to demangle symbol: {mangled}") from e

    def demangle(self, mangled: str) -> dict:
        try:
            return self.demangle_ms(mangled, False)
        except Exception as e:
            raise ValueError(f"Unable to demangle symbol: {mangled}") from e
