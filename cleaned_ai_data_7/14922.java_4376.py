import unittest
from unittest.mock import patch

class SpellbookDaoImplTest(unittest.TestCase):
    def __init__(self):
        super().__init__()
        self.dao = SpellbookDaoImpl()

    @patch('com.iluwatar.servicelayer.spellbook.Spellbook')
    def test_find_by_name(self, mock_spellbook):
        all_books = self.dao.find_all()
        for book in all_books:
            spellbyname = self.dao.find_by_name(book.name)
            self.assertIsNotNone(spellbyname)
            self.assertEqual(book.id, spellbyname.id)
            self.assertEqual(book.name, spellbyname.name)

if __name__ == '__main__':
    unittest.main()
