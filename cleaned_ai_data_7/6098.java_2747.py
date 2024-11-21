class ListingTest:
    def __init__(self):
        pass

    @classmethod
    def setUp(cls):
        builder = ToyProgramBuilder("Test", True)
        program = builder.get_program()
        space = program.get_address_space()
        listing = program.get_listing()
        mem = program.get_memory()

    @classmethod
    def tearDown(cls):
        program.end_transaction(True)

    def test_get_function_with_namespace(self):
        listing.create_function("bob", 0x1000, AddressSet(0x1000, 0x1100), SourceType.USER_DEFINED)
        namespace1 = symbol_table.create_name_space(program.get_global_namespace(), "foo", SourceType.USER_DEFINED)
        namespace2 = symbol_table.create_name_space(namespace1, "bar", SourceType.USER_DEFINED)

        listing.create_function("bob", namespace2, 0x2000, AddressSet(0x2000, 0x2100), SourceType.USER_DEFINED)

        functions = listing.get_functions("foo::bar", "bob")
        self.assertEqual(len(functions), 1)

    def test_get_function_with_colon_in_name_and_with_namespace(self):
        listing.create_function("bob::sis", 0x1000, AddressSet(0x1000, 0x1100), SourceType.USER_DEFINED)
        namespace1 = symbol_table.create_name_space(program.get_global_namespace(), "foo::bar", SourceType.USER_DEFINED)
        namespace2 = symbol_table.create_name_space(namespace1, "baz", SourceType.USER_DEFINED)

        listing.create_function("bob::sis", namespace2, 0x2000, AddressSet(0x2000, 0x2100), SourceType.USER_DEFINED)

        functions = listing.get_functions("foo::bar::baz", "bob::sis")
        self.assertEqual(len(functions), 1)
        f = functions[0]
        self.assertIsNotNone(f)
        self.assertEqual(f.name(), "bob::sis")
        self.assertEqual(f.full_name(), "foo::bar::baz::bob::sis")
        self.assertEqual(f.short_name(), "bob::sis")
        self.assertEqual(f.parent_namespace().name, "baz")
        self.assertEqual(f.parent_namespace().parent_namespace().name, "foo::bar")
        self.assertEqual(f.parent_namespace().parent_namespace().parent_namespace().id, Namespace.GLOBAL_NAMESPACE_ID)

    def addr(self, l):
        return space.get_address(l)
