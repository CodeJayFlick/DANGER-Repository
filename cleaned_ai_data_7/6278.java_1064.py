import unittest
from ghidra.app.plugin.core.commentwindow import CommentWindowPlugin
from ghidra.framework.plugintool import PluginTool
from ghidra.program.model.address import AddressFactory
from ghidra.program.model.listing import CodeUnit, Program

class TestCommentWindowPlugin(unittest.TestCase):

    def setUp(self):
        self.env = None
        self.tool = None
        self.addr_factory = None
        self.program = None
        self.plugin = None
        self.browser = None
        self.comment_table = None
        self.provider = None

    def test_navigation(self):
        num_rows = len(comment_table)
        for i in range(num_rows):
            click_cell(comment_table, i, 2)  # Assuming the second column is the location column
            address = browser.get_current_address()
            table_addr = address.get_address(str(comment_table[i][0]))  # Assuming the first column contains addresses as strings
            self.assertEqual(address, table_addr)

    def test_comment_removed_and_restored(self):
        assert len(comment_table) == 5

        clear_comments(addr(0x010018cf))

        assert len(comment_table) == 4

        program.undo()
        assert len(comment_table) == 5

    def test_comment_added_and_restored(self):
        num_comments = len(comment_table)

        self.assertEqual(num_comments, 5)

        add_comment(addr("0x01001000"), CodeUnit.EOL_COMMENT, "Added EOL Comment")

        assert len(comment_table) == 6

        program.undo()
        wait_for_table()

        assert len(comment_table) == 5

    def test_comment_changed_and_restored(self):
        num_comments = len(comment_table)

        self.assertEqual(num_comments, 5)

        row_index = get_row_index(addr("0x01006420"))
        self.assertNotEqual(row_index, -1)

        # Test to see if the comment we expect is in the table
        self.assertEqual(get_comment(row_index), "test EOL comment")

        set_comment(addr("0x01006420"), CodeUnit.EOL_COMMENT, "Changed EOL Comment")

        # Test to see if the changed comment is in the table
        self.assertEqual(get_comment(row_index), "Changed EOL Comment")

        program.undo()
        wait_for_table()

        self.assertEqual(get_comment(row_index), "test EOL comment")

    def test_program_close(self):
        close_program()

        wait_for_table()

        self.assertEqual(len(comment_table), 0)
        load_program("notepad")

    def add_comment(self, addr, comment_type, comment):
        program.start_transaction()
        try:
            program.get_listing().set_comment(addr, comment_type, comment)
        finally:
            program.end_transaction(True)

        wait_for_table()

    def clear_comments(self, start_addr, end_addr=None):
        if end_addr is None:
            end_addr = addr(start_addr + 1)

        program.start_transaction()
        try:
            program.get_listing().clear_comments(start_addr, end_addr)
        finally:
            program.end_transaction(True)

        wait_for_table()

    def get_row_index(self, address):
        for i in range(len(comment_table)):
            if comment_table[i][0] == str(address):
                return i
        return -1

    def set_comment(self, addr, comment_type, comment):
        program.start_transaction()
        try:
            program.get_listing().set_comment(addr, comment_type, comment)
        finally:
            program.end_transaction(True)

        wait_for_table()

if __name__ == '__main__':
    unittest.main()
