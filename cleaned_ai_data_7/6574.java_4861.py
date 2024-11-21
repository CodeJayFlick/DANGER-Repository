import random

class ObjectPropertyMapDBTest:
    def __init__(self):
        self.db = None
        self.program = None
        self.addr_space = None
        self.mem_map = None
        self.addr_map = None
        self.property_map = None
        self.random = random.Random(1)
        self.transaction_id = 0

    @classmethod
    def setUp(cls):
        cls.program = create_default_program("Test", "TOY")
        cls.db = cls.program.get_db_handle()
        cls.addr_space = cls.program.get_address_factory().get_default_address_space()
        cls.mem_map = cls.program.get_memory()
        cls.addr_map = getInstanceField("addrMap", mem_map)
        cls.transaction_id = cls.program.start_transaction("Test")

    @classmethod
    def tearDown(cls):
        cls.program.end_transaction(cls.transaction_id, True)

    def create_property_map(self, name):
        self.property_map = ObjectPropertyMapDB(self.db, DBConstants.CREATE, None, addr_space, name,
                                                  TestSaveable, TaskMonitorAdapter.DUMMY_MONITOR, True)
        self.property_map.set_cache_size(2)

    @classmethod
    def test_object_property_map_db(cls):
        cls.create_property_map("TEST")
        assert null(cls.db.get_table(cls.property_map.get_table_name()))  # Table created when first value added

    @classmethod
    def test_get_name(cls):
        cls.create_property_map("TEST")
        assertEquals("TEST", cls.property_map.get_name())

    @classmethod
    def test_add(cls):
        cls.create_property_map("TEST")

        property_table = None
        for i in range(20):
            obj = create_save_objectable()
            cls.property_map.add(addr(i * 100), obj)
            if i == 0:
                property_table = cls.db.get_table(cls.property_map.get_table_name())
                assert not null(property_table)

    @classmethod
    def test_get_object(cls):
        cls.create_property_map("TEST")

        for i in range(20):
            obj = create_save_objectable()
            cls.property_map.add(addr(i * 100), obj)
        for i in range(20):
            obj = cls.property_map.get_object(addr(i * 100))
            assertEquals(obj, save_objects[i])

    @classmethod
    def test_get_size(cls):
        cls.create_property_map("TEST")

        property_table = None
        for i in range(20):
            obj = create_save_objectable()
            cls.property_map.add(addr(i * 100), obj)
        assertEquals(cls.property_map.get_size(), 20)

    @classmethod
    def test_apply_value(cls):
        my_visitor = MyObjectVisitor()

        cls.create_property_map("TEST")

        for i in range(20):
            obj = create_save_objectable()
            cls.property_map.add(addr(i * 100), obj)
        for i in range(20):
            cls.property_map.apply_value(my_visitor, addr(i * 100))
            assertEquals(my_visitor.value, save_objects[i])

    @classmethod
    def test_delete(cls):
        cls.create_property_map("TEST")

        property_table = None
        for i in range(20):
            obj = create_save_objectable()
            cls.property_map.add(addr(i * 100), obj)
        cls.property_map.delete()

    # More tests...

class MyObjectVisitor:
    def __init__(self):
        self.value = None

    @classmethod
    def visit(cls, value1):
        raise RuntimeException()

# Helper functions...
def create_save_objectable():
    obj = TestSaveableObject()
    obj.boolean_value = random.randint(0, 1)
    obj.byte_value = random.getrandbits(8)
    obj.short_value = random.getrandbits(16)
    obj.int_value = random.getrandbit
