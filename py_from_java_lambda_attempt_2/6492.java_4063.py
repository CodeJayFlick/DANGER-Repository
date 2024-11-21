Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.codebrowser import CodeBrowserPlugin
from ghidra.framework.options import Options
from ghidra.program.database import ProgramDB
from ghidra.program.model.address import Address, AddressFactory
from ghidra.program.model.listing import Listing

class EolCommentFieldFactoryTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        program = build_program()
        self.cb = env.launch_default_tool(program)
        field_options = cb.get_format_manager().get_field_options()

    def tearDown(self):
        env.dispose()

    @unittest.skip("Not implemented yet")
    def test_word_wrapping(self):
        function = find_first_function()
        set_comment_in_function(function, "comment line 1\ncomment line 2")

        change_field_width_to_half_comment_length(function)

        tf = get_field_text(function)
        self.assertEqual(2, tf.get_num_rows())

        cb.set_boolean_option("ENABLE_WORD_WRAP_MSG", True)

        tf = get_field_text(function)
        self.assertEqual(4, tf.get_num_rows())

    @unittest.skip("Not implemented yet")
    def test_repeatable_comment_function_call(self):
        # check existing auto comment
        tf = get_field_text(addr("0x010022e6"))
        self.assertEqual(1, tf.get_num_rows())
        self.assertTrue(tf.get_text().startswith("undefined ghidra(undefined4 param_1,"))

        destination = addr("0x01002cf5")
        repeatable_comment = "My repeatable comment"
        set_repeatable_comment(destination, repeatable_comment)

        # check that the auto comment now matches the updated comment
        tf = get_field_text(addr("0x010022e6"))
        self.assertEqual(1, tf.get_num_rows())
        self.assertEqual(tf.get_text(), repeatable_comment)

    @unittest.skip("Not implemented yet")
    def test_repeatable_comment_data_access(self):
        # check existing auto comment
        tf = get_field_text(addr("0x01002265"))
        self.assertEqual(1, tf.get_num_rows())
        self.assertTrue(tf.get_text().startswith("="))

        destination = addr("0x01002265")
        repeatable_comment = "My repeatable comment"
        set_repeatable_comment(destination, repeatable_comment)

        # check that the auto comment now matches the updated comment
        tf = get_field_text(addr("0x01002265"))
        self.assertEqual(1, tf.get_num_rows())
        self.assertEqual(tf.get_text(), repeatable_comment)

    def build_program(self):
        builder = ClassicSampleX86ProgramBuilder()
        return builder.get_program()

    def set_comment_in_function(self, function, comment):
        cu = program.get_listing().get_code_unit_at(function.get_entry_point())
        transaction_id = program.start_transaction("test")
        try:
            cu.set_comment(CodeUnit.EOL_COMMENT, comment)
        finally:
            program.end_transaction(transaction_id, True)

    def find_first_function(self):
        listing = program.get_listing()
        iter = listing.get_functions(True)
        function = next(iter)
        self.assertIsNotNone(function)
        return function

    def change_field_width_to_half_comment_length(self, function):
        tf = get_field_text(function)
        field_element = tf.get_field_element(0, 0)
        string_width = field_element.get_string_width()
        set_field_width(tf.get_factory(), string_width // 2)

    def get_field_text(self, address):
        self.assertTrue(cb.go_to_field(address, EolCommentFieldFactory.FIELD_NAME, 1, 1))
        tf = cb.get_current_field()
        return tf

    def set_repeatable_comment(self, destination, comment):
        set_comment(destination, CodeUnit.REPEATABLE_COMMENT, comment)

    def addr(self, address):
        factory = program.get_address_factory()
        return factory.get_address(address)

# Private Methods
def tx(program, func):
    transaction_id = program.start_transaction("test")
    try:
        func()
    finally:
        program.end_transaction(transaction_id, True)
```

Note that this is a direct translation of the Java code into Python. The original code was not tested and may contain bugs or errors.