import unittest
from hamcrest import assert_that, not_

class ReflectionUtilitiesTest(unittest.TestCase):

    def test_get_class_name_after(self):
        caller = get_class_name_older_than(ReflectionUtilitiesTest)
        self.assertNotEqual(caller, type(self).__name__)

    def test_get_class_name_after_no_classes(self):
        caller = get_class_name_older_than()
        self.assertEqual(caller, ReflectionUtilitiesTest.__name__)

    def test_get_class_name_after_invalid_classes(self):
        try:
            get_class_name_older_than(SystemUtilities)
            self.fail("Did not get an exception passing a class not in the stack")
        except Exception as e:
            pass

    def test_get_class_name_after_another_class(self):
        nested = NestedTestClass()
        caller = nested.get_caller_from_one_level()
        self.assertEqual(caller, ReflectionUtilitiesTest.__name__)

    def test_move_past_stack_trace_pattern(self):
        trace = [
            {"class": "Class1", "method": "method"},
            {"class": "Class2", "method": "method"},
            {"class": "Class3", "method": "method"},
            {"class": "OtherClass", "method": "otherCall"},
            {"class": "ThirdClass", "method": "doIt"},
            {"class": "FinalClass", "method": "maybeDoIt"}
        ]
        updated = move_past_stack_trace_pattern(trace, "method")
        self.assertEqual(len(updated), 4)
        self.assertEqual(updated[0]["class"], "OtherClass.class")
        self.assertEqual(updated[-1]["class"], "Class3.class")

    def test_create_filteredThrowable(self):
        t = create_filtered_ throwable("org.junit")
        updated = t.get_stack_trace()
        for element in updated:
            assert_that(element, not_(contains_string("org.junit")))

    # verify that we can discover parent template types when given a subclass implementation
    def test_runtime_type_discovery(self):
        runtime_base_type = RuntimeBaseType()
        type_arguments = get_type_arguments(type(RuntimeBaseType), type(runtime_base_type))
        self.assertFalse(type_arguments.empty)
        self.assertIsNone(type_arguments[0])
        self.assertIsNone(type_arguments[1])

        pass_through_type = ChildTypeWithPassThroughTypes()
        type_arguments = get_type_arguments(type(RuntimeBaseType), type(pass_through_type))
        self.assertFalse(type_arguments.empty)
        self.assertIsNone(type_arguments[0])
        self.assertIsNone(type_arguments[1])

        actual_type = ChildTypeWithActualTypes()
        type_arguments = get_type_arguments(type(RuntimeBaseType), type(actual_type))
        self.assertFalse(type_arguments.empty)
        self.assertEqual(type_arguments[0], str.__class__)
        self.assertEqual(type_arguments[1], object.__class__)

    def test_runtime_type_discovery_null(self):
        with self.assertRaises(NullPointerException):
            get_type_arguments(list, None)

    def test_rumtime_type_discovery_anonymous_class(self):
        myList = list()
        types = get_type_arguments(list, type(myList))
        self.assertEqual(len(types), 1)
        self.assertEqual(types[0], str.__class__)

    def test_runtime_type_discovery_local_variable(self):
        myList = list()
        types = get_type_arguments(list, type(myList))
        self.assertEqual(len(types), 1)
        self.assertIsNone(types[0])

    def test_runtime_type_discovery_mixed_hierarchy_abstract_class_and_interface_both_define_values(self):
        types = get_type_arguments(RuntimeBaseInterface, ChildExtendingPartiallyDefinedTypes.__class__)
        self.assertEqual(len(types), 2)
        self.assertEqual(types[0], str.__class__)
        self.assertEqual(types[1], float.__class__)

    def test_runtime_type_discovery_sub_interface Defines_values(self):
        types = get_type_arguments(RuntimeBaseInterface, ChildExtendingWhollyDefinedTypes.__class__)
        self.assertEqual(len(types), 2)
        self.assertEqual(types[0], str.__class__)
        self.assertEqual(types[1], float.__class__)

    def test_runtime_type_discovery_mixed_hierarchy_unrelated_parents(self):
        types = get_type_arguments(RuntimeBaseInterface, ChildWithMixedParentTypes.__class__)
        self.assertEqual(len(types), 2)
        self.assertEqual(types[0], int.__class__)
        self.assertEqual(types[1], float.__class__)

def element(class_name, method_name):
    return {"class": class_name + ".class", "method": method_name}

class NestedTestClass:
    def get_caller_from_one_level(self):
        name = get_class_name_older_than(type(NestedTestClass))
        return name

    def get_caller_from_two_levels(self):
        caller = self.level_two()
        return caller

    def level_two(self):
        name = get_class_name_older_than(type(NestedTestClass))
        return name

def move_past_stack_trace_pattern(trace, method_name):
    updated = [element(class_name=class_name["class"], method_name=method_name) for class_name in trace]
    return updated

def create_filteredThrowable(package_name):
    t = Exception()
    t.stack_info = {"stack": [{"class": package_name + ".class", "method": "otherCall"}]}
    return t

def get_class_name_older_than(cls=None):
    if cls is None:
        return type(ReflectionUtilitiesTest).__name__
    else:
        return cls.__name__

def get_type_arguments(parent_type, child_type):
    types = []
    for attr in dir(child_type):
        value = getattr(child_type, attr)
        if isinstance(value, tuple) and len(value) > 0:
            types.extend(value[1:])
    return [type(type_) for type_ in set(types)]

if __name__ == "__main__":
    unittest.main()
