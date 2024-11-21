import unittest
from ghidra.dbg.target import TargetObject, TargetActiveScope
from ghidra.dbg.util import PathPattern


class AbstractModelForLldbActivationTest(unittest.TestCase):

    def test_default_focus_is_as_expected(self):
        expected_default_focus = self.get_expected_default_active_path()
        assume(expected_default_focus is not None)
        self.m.build()

        path_pattern = PathPattern(expected_default_focus)

        activatable_objects = self.get_activatable_things()
        obj = next((obj for obj in activatable_objects if path_pattern.matches(obj.path)), None)
        if self.m.has_interpreter():
            interpreter = self.find_interpreter()
            self.assert_active_via_interpreter(obj, interpreter)

    def test_activate_each_once(self):
        self.m.build()

        active_scope = self.find_active_scope()
        activatable_objects = self.get_activatable_things()
        for obj in activatable_objects:
            active_scope.request_activation(obj)
            if self.m.has_interpreter():
                interpreter = self.find_interpreter()
                self.assert_active_via_interpreter(obj, interpreter)

    def test_activate_each_twice(self):
        self.m.build()

        active_scope = self.find_active_scope()
        activatable_objects = self.get_activatable_things()
        for obj in activatable_objects:
            active_scope.request_activation(obj)
            if self.m.has_interpreter():
                interpreter = self.find_interpreter()
                self.assert_active_via_interpreter(obj, interpreter)

            active_scope.request_activation(obj)
            if self.m.has_interpreter():
                interpreter = self.find_interpreter()
                self.assert_active_via_interpreter(obj, interpreter)

    def test_activate_each_via_interpreter(self):
        assume(self.m.has_interpreter())
        self.m.build()

        activatable_objects = self.get_activatable_things()
        for obj in activatable_objects:
            self.activate_via_interpreter(obj)
            self.assert_active_via_interpreter(obj)

    # Helper methods
    def get_expected_default_active_path(self):
        pass

    def get_activatable_things(self):
        pass

    def find_active_scope(self):
        pass

    def find_interpreter(self):
        pass

    def assert_active_via_interpreter(self, obj, interpreter):
        pass

    def activate_via_interpreter(self, obj):
        pass
