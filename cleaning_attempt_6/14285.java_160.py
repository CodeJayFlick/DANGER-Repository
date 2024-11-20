import unittest
from unittest.mock import patch, mock_open, ANY

class MenuViewTest(unittest.TestCase):

    @patch('com.iluwatar.flux.store.MenuStore')
    def test_store_changed(self, menu_store):
        store = menu_store.return_value
        store.getSelected.return_value = 'HOME'

        view = MenuView()
        view.storeChanged(store)

        self.assertEqual(menu_store.call_count, 1)
        self.assertEqual(store.getSelected.call_count, 1)

    @patch('com.iluwatar.flux.dispatcher.Dispatcher')
    def test_item_clicked(self, dispatcher):
        store = mock_open().return_value
        dispatcher.registerStore.return_value = store

        view = MenuView()
        view.itemClicked('PRODUCTS')

        self.assertEqual(store.onAction.call_count, 2)

if __name__ == '__main__':
    unittest.main()
