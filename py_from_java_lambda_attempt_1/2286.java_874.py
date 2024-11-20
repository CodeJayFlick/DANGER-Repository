Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from abc import ABCMeta, abstractmethod


class AbstractDebuggerModelRegistersTest(metaclass=ABCMeta):
    @abstractmethod
    def get_expected_register_bank_path(self, thread_path: list) -> list:
        pass

    @abstractmethod
    def is_register_bank_also_container(self) -> bool:
        pass

    @abstractmethod
    def get_register_writes(self) -> dict:
        pass


class Test(AbstractDebuggerModelRegistersTest):
    def __init__(self):
        self.m = None  # Initialize this later, probably in a test method.

    def build(self):
        if not self.m:  # Check if m is initialized.
            raise Exception("m must be initialized before calling build.")

    @unittest.skipIf(not hasattr(unittest.TestCase, 'assertNotNull'), "Old unittest version")
    def assert_not_null(self, value):
        if value is None:
            raise AssertionError()

    def test_register_bank_is_where_expected(self):
        self.build()
        target = maybe_substitute_thread(obtain_target())
        expected_register_bank_path = get_expected_register_bank_path(target.path)
        assumeNotNull(expected_register_bank_path)

        bank = find_register_bank(target.path)
        self.assertEqual(bank.path, expected_register_bank_path)

    def test_banks_are_containers_convention_is_as_expected(self):
        self.build()

        banks_are_containers = True
        for schema in self.m.model.get_root_schema().get_context().get_all_schemas():
            if isinstance(schema, TargetRegisterBank) and issubclass(schema, TargetRegisterContainer):
                banks_are_containers &= (schema. get_interfaces() & set([TargetRegisterContainer]))
        self.assertEqual(is_register_bank_also_container(), banks_are_containers)

    def test_registers_have_expected_sizes(self):
        self.build()

        target = maybe_substitute_thread(obtain_target())
        bank = find_register_bank(target.path)
        descriptions = bank.get_descriptions()
        for ent in get_register_writes().items():
            reg_name, value = ent
            reg = find_register(reg_name, descriptions.path)
            self.assertEqual(len(value), (reg.bit_length() + 7) // 8)

    def test_read_registers(self):
        self.build()

        target = maybe_substitute_thread(obtain_target())
        bank = find_register_bank(target.path)
        exp = get_register_writes()
        read = wait_on(bank.read_registers_named(exp.keys()))
        self.assertEqual("Not all registers were read, or extras were read", set(exp), set(read))

        for name in exp:
            self.assertEqual(len(exp[name]), len(read[name]))

    def test_write_registers(self):
        self.build()

        target = maybe_substitute_thread(obtain_target())
        bank = find_register_bank(target.path)
        write = get_register_writes()
        wait_on(bank.write_registers_named(write))
        read = wait_on(bank.read_registers_named(write.keys()))
        for name in write:
            self.assertListEqual(list(write[name]), list(read[name]))

    def expect_register_object_value(self, bank: TargetRegisterBank, name: str, value: bytes):
        retry_void(lambda: 
            reg = find_register(name, bank.path)
            assert_not_null(reg)
            actual_hex = str(reg.get_value())
            assert_not_null(actual_hex)
            self.assertEqual(new_big_integer(value), new_big_integer(actual_hex, 16))

    def maybe_substitute_thread(self, target):
        # This method should be implemented in the subclass.
        pass

    def obtain_target(self):
        # This method should be implemented in the subclass.
        pass


class TargetRegisterBank:
    @abstractmethod
    def get_descriptions(self) -> object:
        pass

    @abstractmethod
    def read_registers_named(self, names: set) -> dict:
        pass

    @abstractmethod
    def write_registers_named(self, writes: dict):
        pass


def find_register_bank(path: list) -> TargetRegisterBank:
    # This method should be implemented in the subclass.
    pass


def wait_on(task: object):
    # This method should be implemented in the subclass.
    pass

def new_big_integer(value: bytes, base: int = 2) -> BigInteger:
    return BigInteger(1, value)


class TargetRegisterContainer(metaclass=ABCMeta):
    @abstractmethod
    def get_interfaces(self) -> set:
        pass


class TargetObjectSchema(metaclass=ABCMeta):
    @abstractmethod
    def get_root_schema(self) -> object:
        pass

    @abstractmethod
    def get_context(self) -> object:
        pass

    @abstractmethod
    def get_all_schemas(self) -> list:
        pass


def find_register(name: str, path: list) -> TargetRegister:
    # This method should be implemented in the subclass.
    pass
```

Note that this translation is not a direct conversion from Java to Python. It's more like an equivalent implementation of the same logic using Python syntax and features.