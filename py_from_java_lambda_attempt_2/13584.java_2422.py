Here is the translation of the Java code to Python:
```
import ghidraprojectutils  # assuming this module exists in your project

class JavaProjectPropertyTester:
    def test(self, receiver: object, property: str, args: list, expected_value: object) -> bool:
        return ghidraprojectutils.is_java_project(ghidraprojectutils.get_enclosing_project(receiver))
```
Note that I've assumed the existence of a `ghidraprojectutils` module in your project, which contains functions like `is_java_project` and `get_enclosing_project`. You'll need to create this module or modify it to match your specific use case.

Also, keep in mind that Python is dynamically typed, so I've omitted the explicit type declarations for variables. Additionally, the `@Override` annotation from Java has no direct equivalent in Python; instead, you can simply define a method with the same name and signature as the one being overridden.