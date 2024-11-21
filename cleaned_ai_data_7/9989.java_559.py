import unittest

class TestMenuData(unittest.TestCase):

    def test_menu_data_parses_mnemonic_from_ampersand(self):
        menu_data = MenuData(["One", "Two", "&Three"])
        self.assertEqual(menu_data.get_mnemonic(), 'T')

    def test_menu_data_passed_mnemonic_wins(self):
        menu_data = MenuData(["One", "Two", "&Three"], None, None, 'h', None)
        self.assertEqual(menu_data.get_mnemonic(), 'h')

    def test_break_menu_path(self):
        try:
            menu_data = MenuData([])
            menu_data.set_menu_path([])
        except Exception as e:
            self.assertIsInstance(e, ValueError)

    def test_break_menu_path2(self):
        try:
            MenuData([])
        except Exception as e:
            self.assertIsInstance(e, ValueError)

    def test_set_menu_item_name(self):
        menu_data = MenuData(["One", "Two", "T&hree"])
        self.assertEqual(menu_data.get_menu_item_name(), 'Three')
        self.assertEqual(menu_data.get_mnemonic(), 'h')

        new_name = 'Completely New Name'
        menu_data.set_menu_item_name(new_name)
        self.assertEqual(menu_data.get_mnemonic(), MenuData.NO_MNEMONIC)

    def test_set_menu_path(self):
        menu_data = MenuData(["One", "Two", "T&hree"])
        self.assertEqual(menu_data.get_menu_item_name(), 'Three')
        self.assertEqual(menu_data.get_mnemonic(), 'h')

        new_name = 'Completely New Name'
        new_path = ['Four', new_name]
        menu_data.set_menu_path(new_path)
        self.assertEqual(menu_data.get_mnemonic(), MenuData.NO_MNEMONIC)

if __name__ == '__main__':
    unittest.main()
