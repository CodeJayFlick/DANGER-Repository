Here is the translation of the Java code into Python:

```Python
import os
import shutil
from itertools import filterfalse

class TestUtilities:
    def __init__(self):
        pass

    @staticmethod
    def get_test_suite(pkg_name: str) -> list:
        test_cases = []
        for root, dirs, files in os.walk(pkg_name):
            for file in files:
                if file.endswith('.java'):
                    filename = os.path.join(root, file)
                    with open(filename, 'r') as f:
                        content = f.read()
                        if "public class" in content and "extends TestCase" in content:
                            test_cases.append(os.path.basename(file).replace('.java', ''))

        return test_cases

    @staticmethod
    def create_test_suite(pkg_name: str) -> None:
        suite = TestSuite()
        for case in get_test_suite(pkg_name):
            try:
                class_ = __import__(case)
                if issubclass(class_, unittest.TestCase):
                    suite.addTest(unittest.makeSuite(class_))
            except ImportError as e:
                print(f"Failed to load test case: {e}")

    @staticmethod
    def create_all_tests(base_dir_path: str, class_name: str, top_package: str) -> None:
        base_dir = os.path.abspath(os.path.expanduser(base_dir_path))
        if not os.path.exists(base_dir):
            print(f"TestUtilities: invalid directory ({base_dir})")
            return

        for root, dirs, files in os.walk(top_package):
            for file in files:
                filename = os.path.join(root, file)
                with open(filename, 'r') as f:
                    content = f.read()
                    if "public class" in content and "extends TestCase" in content:
                        test_suite_name = f"{class_name}_{os.path.basename(file).replace('.java', '')}"
                        suite_dir = os.path.join(base_dir, root.replace(top_package + '/', ''))
                        os.makedirs(suite_dir, exist_ok=True)
                        with open(os.path.join(suite_dir, f"{test_suite_name}.py"), 'w') as out:
                            out.write(f"import unittest\nfrom {root.replace('/', '.')}.{file[:-5]} import TestSuite\nclass {test_suite_name}(unittest.TestCase):\n    def test_all(self): pass")
```

This Python code does not have a direct equivalent to the Java `main` method. Instead, it defines three static methods: `get_test_suite`, `create_test_suite`, and `create_all_tests`. These methods can be called from other parts of your program or even from outside your program using an interpreter like IDLE.

The Python code does not include any JUnit test cases because the Java code you provided was focused on creating a TestSuite for each package.