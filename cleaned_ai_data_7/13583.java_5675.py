import ghidraprojectutils  # assuming this module exists in your project

class GhidraProjectPropertyTester:
    def test(self, receiver: object, property: str, args: list, expected_value: object) -> bool:
        return ghidraprojectutils.is_ghidra_project(ghidraprojectutils.get_enclosing_project(receiver))
