import unittest
from ghidra.app.util.viewer.field import PreCommentFieldFactoryTest
from ghidra.framework.options import Options
from ghidra.program.database import ProgramDB
from ghidra.program.model.address import Address, AddressFactory

class TestPreCommentFieldFactory(unittest.TestCase):

    def setUp(self):
        self.env = None
        self.tool = None
        self.cb = None
        self.field_options = None
        self.program = build_program()

    def tearDown(self):
        if self.env:
            self.env.dispose()
        del self.env, self.tool, self.cb, self.field_options

    def test_flag_function_entry(self):
        set_boolean_option(PreCommentFieldFactory.FLAG_FUNCTION_ENTRY_OPTION, True)
        listing = program.get_listing()
        function_iter = listing.get_functions(True)
        while function_iter.has_next():
            f = function_iter.next()
            tf = get_field_text(f)
            self.assertEqual(PreCommentFieldFactory.FUNCTION_FLAG_COMMENT, tf.text)

    def test_existing_pre_comment(self):
        function = find_first_function()

        set_comment_in_function(function, "My pre comment")

        set_boolean_option(PreCommentFieldFactory.FLAG_FUNCTION_ENTRY_OPTION, True)

        tf = get_field_text(function)
        self.assertEqual("\n|||||||||||||||||| FUNCTION ||||||||||||||||||\n My pre comment", tf.text)

        set_boolean_option(PreCommentFieldFactory.ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG, False)

        tf = get_field_text(function)
        self.assertEqual("My pre comment", tf.text)

    def test_flag_subroutine_entry(self):
        cb.go_to_field(addr("1001200"), PreCommentFieldFactory.FIELD_NAME, 1, 1)

        set_boolean_option(PreCommentFieldFactory.FLAG_SUBROUTINE_ENTRY_OPTION, True)
        self.assertTrue(cb.go_to_field(addr("1001200"), PreCommentFieldFactory.FIELD_NAME, 1, 1))
        tf = cb.current_field
        self.assertEqual(PreCommentFieldFactory.SUBROUTINE_FLAG_COMMENT, tf.text)

    def test_word_wrapping(self):
        function = find_first_function()

        set_comment_in_function(function, "comment line 1\ncomment line 2")

        change_field_width_to_half_comment_length(function)

        tf = get_field_text(function)
        self.assertEqual(2, tf.num_rows())

        set_boolean_option(PreCommentFieldFactory.ENABLE_WORD_WRAP_MSG, True)

        tf = get_field_text(function)
        self.assertEqual(4, tf.num_rows())

    def build_program(self):
        builder = ToyProgramBuilder("notepad", True)
        builder.create_memory(".text", "0x1001000", 0x6600)
        builder.create_empty_function(None, "1001000", 1000, None)
        builder.create_return_instruction("1001000")

        builder.create_memory_call_reference("1001100", "1001200")
        builder.create_return_instruction("1001200")
        return builder.get_program()

    def set_comment_in_function(self, function, comment):
        cu = program.get_listing().get_code_unit_at(function.entry_point)
        transaction_id = program.start_transaction("test")
        try:
            cu.set_comment(CodeUnit.PRE_COMMENT, comment)
        finally:
            program.end_transaction(transaction_id, True)

    def find_first_function(self):
        listing = program.get_listing()
        function_iter = listing.get_functions(True)
        function = function_iter.next()
        self.assertIsNotNone(function)
        return function

    def change_field_width_to_half_comment_length(self, function):
        tf = get_field_text(function)
        field_element = tf.field_elements[0][0]
        string_width = field_element.string_width
        set_field_width(tf.get_factory(), string_width // 2)

    def get_field_text(self, function):
        self.assertTrue(cb.go_to_field(function.entry_point, PreCommentFieldFactory.FIELD_NAME, 1, 1))
        return cb.current_field

    def set_field_width(self, factory, width):
        SwingUtilities.invokeLater(lambda: factory.set_width(width))
        waitForPostedSwingRunnables()
        cb.update_now()

    def set_boolean_option(self, name, value):
        SwingUtilities.invokeLater(lambda: self.field_options.set_boolean(name, value))
        waitForPostedSwingRunnables()
        cb.update_now()

    def addr(self, address):
        return AddressFactory(program).get_address(address)

if __name__ == "__main__":
    unittest.main()
