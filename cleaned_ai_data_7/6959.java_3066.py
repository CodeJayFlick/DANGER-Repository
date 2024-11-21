import unittest
from ghidra_app.decompiler import DecompilerProvider
from ghidra_app.plugin.core.decompile import DecompilePlugin
from docking.widgets.fieldpanel import FieldPanel
from docking.widgets.fieldpanel.field import Field
from ghidra.program.model.pcode import HighFunction

class AbstractDecompilerTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.decompiler = get_plugin(tool, DecompilePlugin)
        self.provider = get_decompiler_provider()

    def tearDown(self):
        wait_for_decompiler()
        super().tearDown()

    def decompile(self, addr):
        go_to(addr)
        wait_for_decompiler()

    def set_decompiler_location(self, line, char_position):
        panel = provider.get_decompiler_panel()
        fp = panel.get_field_panel()
        loc = self.loc(line, char_position)

        # scroll to the field to make sure it has been built so that we can get its point
        fp.scroll_to(loc)
        p = fp.get_point_for_location(loc)

        click(fp, p, 1, True)
        wait_for_swing()

    def double_click(self):
        panel = provider.get_decompiler_panel()
        fp = panel.get_field_panel()
        self.click(fp, 2, True)
        wait_for_swing()

    def loc(self, line_number, col):
        return FieldLocation(line_number - 1, 0, 0, col)

    def get_field_for_line(self, provider, line_number):
        panel = provider.get_decompiler_panel()
        fields = panel.get_fields()
        field = fields[line_number - 1]
        return ClangTextField(field)

    def get_token(self, line, col):
        return self.get_token(loc(line, col))

    def get_token(self, loc):
        return self.get_token(provider, loc)

    def get_token(self, provider, loc):
        panel = provider.get_decompiler_panel()
        field = panel.get_fields()[loc.index]
        token = field.get_token(loc)
        return token

    def get_decompiler_panel(self):
        return provider.get_decompiler_panel()

    def get_high_function(self):
        return self.provider.get_controller().get_high_function()

    # note: the index is 0- based; use get_field_for_line() when using 1-based line numbers
    def get_token_text(self, loc):
        token = self.get_token(loc)
        return token.text

    def assert_token(self, token_text, line, *cols):
        for col in cols:
            token = self.get_token(line, col)
            text = token.text
            self.assertEqual(token_text, text)

    # note: the index is 0- based; use get_field_for_line() when using 1-based line numbers
    def assert_token(self, token_text, line_index):
        field = self.get_field_for_line(provider, line_index)
        token = field.get_token()
        text = token.text
        self.assertEqual(token_text, text)

    # note: the index is 0- based; use get_field_for_line() when using 1-based line numbers
    def assert_token(self, token_text):
        panel = provider.get_decompiler_panel()
        loc = panel.get_cursor_position()
        field = self.get_field_for_line(provider, loc.index)
        token = field.get_token(loc)
        text = token.text
        self.assertEqual(token_text, text)

    # note: the index is 0- based; use get_field_for_line() when using 1-based line numbers
    def assert_token(self, provider):
        panel = provider.get_decompiler_panel()
        loc = panel.get_cursor_position()
        field = self.get_field_for_line(provider, loc.index)
        token = field.get_token(loc)
        text = token.text
        self.assertEqual(token_text, text)

if __name__ == '__main__':
    unittest.main()
