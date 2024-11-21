import ghidraprojectutils  # assuming this module exists in your project

class JavaProjectPropertyTester:
    def test(self, receiver: object, property: str, args: list, expected_value: object) -> bool:
        return ghidraprojectutils.is_java_project(ghidraprojectutils.get_enclosing_project(receiver))
