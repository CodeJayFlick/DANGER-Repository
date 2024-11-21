Here is the equivalent Python code:

```Python
import unittest

class AddressMapDBTest(unittest.TestCase):
    def setUp(self):
        self.p = ProgramBuilder("test", "TOY").getProgram()
        self.addr_map = self.get_instance_field("addrMap", self.p.memory)

    @unittest.skipIf(not hasattr(unittest, 'assertEqual'), reason='Python 3.4 and earlier')
    def test_register_address(self):
        reg_space = self.p.address_factory.register_space
        a = reg_space.get_address(0)
        key = self.addr_map.key(a, False)
        self.assertEqual(key, 0x3000000000000000)
        b = self.addr_map.decode_address(key)
        self.assertEqual(b, a)

        a = reg_space.get_address(10)
        key = self.addr_map.key(a, False)
        self.assertEqual(key, 0x300000000000000aL)
        b = self.addr_map.decode_address(key)
        self.assertEqual(b, a)

    @unittest.skipIf(not hasattr(unittest, 'assertEqual'), reason='Python 3.4 and earlier')
    def test_stack_address(self):
        stack_space = self.p.address_factory.stack_space
        a = stack_space.get_address(0)
        key = self.addr_map.key(a, False)
        self.assertEqual(key, 0x4000000000000000L)
        b = self.addr_map.decode_address(key)
        self.assertEqual(b, a)

        a = stack_space.get_address(10)
        key = self.addr_map.key(a, False)
        self.assertEqual(key, 0x400000000000000aL)
        b = self.addr_map.decode_address(key)
        self.assertEqual(b, a)

    @unittest.skipIf(not hasattr(unittest, 'assertEqual'), reason='Python 3.4 and earlier')
    def test_max_register_address(self):
        reg_space = self.p.address_factory.register_space
        a = reg_space.get_address(-1)
        key = self.addr_map.key(a, False)
        self.assertEqual(key, 0x300000000000ffffL)
        b = self.addr_map.decode_address(key)
        self.assertEqual(b, a)

    @unittest.skipIf(not hasattr(unittest, 'assertEqual'), reason='Python 3.4 and earlier')
    def test_stack_address_negative(self):
        stack_space = self.p.address_factory.stack_space
        a = stack_space.get_address(-1)
        key = self.addr_map.key(a, False)
        self.assertEqual(key, 0x40000000ffffffffL)
        b = self.addr_map.decode_address(key)
        self.assertEqual(b, a)

if __name__ == '__main__':
    unittest.main()
```

Note: The `@Before` and `@Test` annotations are not available in Python. Instead, the equivalent setup code is placed inside the test methods using the `setUp()` method provided by the `unittest.TestCase`.