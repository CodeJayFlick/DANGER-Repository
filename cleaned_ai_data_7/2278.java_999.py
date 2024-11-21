import unittest
from typing import Set, List

class AbstractDebuggerModelActivationTest:
    def __init__(self):
        self.m = None  # Assuming this will be set later in a method or constructor.

    def activate_via_interpreter(self, obj: 'TargetObject', interpreter) -> None:
        raise NotImplementedError("Unless hasInterpreter is false, the test must implement this method")

    def assert_active_via_interpreter(self, expected: 'TargetObject', interpreter) -> None:
        raise NotImplementedError("Unless hasInterpreter is false, the test must implement this method")

    @property
    def permit_successor(self):
        return True

    def assert_successor_or_exact(self, expected: 'TargetObject', actual: 'TargetObject') -> None:
        if self.permit_successor and PathUtils.is_ancestor(expected.get_joined_path('.'), actual.get_joined_path('.')):
            print(f"Expected successor of '{expected.get_joined_path('.')}' got '{actual.get_joined_path('.')}'")
        else:
            assert expected == actual

    @property
    def get_expected_default_active_path(self) -> List[str]:
        return None

    class Test(unittest.TestCase):
        def test_default_focus_is_as_expected(self) -> None:
            if self.m.has_interpreter():
                interpreter = find_interpreter()
                obj = Unique.assert_one(get_activatable_things().stream().filter(lambda f: PathUtils.is_ancestor(f.get_path(), get_expected_default_active_path())).collect(Collectors.toList()))
                assertActiveViaInterpreter(obj, interpreter)
            else:
                m.build()

        def test_activate_each_once(self) -> None:
            if self.m.has_interpreter():
                interpreter = find_interpreter()
                for obj in get_activatable_things():
                    activate_via_interpreter(obj, interpreter)
                    retry_void(lambda: assert_successor_or_exact(obj, focus_scope.get_focus()))
                    assertActiveViaInterpreter(obj, interpreter)

        def test_activate_each_twice(self) -> None:
            if self.m.has_interpreter():
                interpreter = find_interpreter()
                for obj in get_activatable_things():
                    activate_via_interpreter(obj, interpreter)
                    retry_void(lambda: assert_successor_or_exact(obj, focus_scope.get_focus()))
                    activate_via_interpreter(obj, interpreter)
                    retry_void(lambda: assert_successor_or_exact(obj, focus_scope.get_focus()))

        def test_activate_each_via_interpreter(self) -> None:
            if self.m.has_interpreter():
                for obj in get_activatable_things():
                    activate_via_interpreter(obj, find_interpreter())
                    retry_void(lambda: assert_successor_or_exact(obj, focus_scope.get_focus()))
                    assertActiveViaInterpreter(obj, find_interpreter())

if __name__ == '__main__':
    unittest.main()
