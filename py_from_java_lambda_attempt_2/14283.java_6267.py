Here is the translation of the Java code to Python:
```python
import unittest
from unittest.mock import MagicMock, patch

class MenuStoreTest(unittest.TestCase):
    def test_on_action(self):
        menu_store = MenuStore()
        
        view = MagicMock(spec=View)
        menu_store.register_view(view)

        # Verify that the view doesn't interact with anything yet
        self.assertEqual(0, view.store_changed.call_count)
        self.assertEqual(None, view.selected)

        # Test that the menu store doesn't react to a content action
        menu_store.on_action(ContentAction(Content.COMPANY))
        self.assertEqual(0, view.store_changed.call_count)
        self.assertEqual(None, view.selected)

        # Test that the menu store reacts to a menu action
        menu_store.on_action(MenuAction(MenuItem.PRODUCTS))
        view.store_changed.assert_called_once_with(menu_store)
        self.assertEqual(MenuItem.PRODUCTS, menu_store.get_selected())

if __name__ == '__main__':
    unittest.main()
```
Note that I used the `unittest` module and the `mock` library from Python's standard library to create mock objects. The rest of the code is straightforward translation from Java to Python.