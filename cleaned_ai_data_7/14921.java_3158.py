import unittest
from unittest.mock import patch

class SpellDaoImplTest(unittest.TestCase):

    def setUp(self):
        self.dao = SpellDaoImpl()

    @patch('SpellDaoImpl.findAll')
    def testFindByName(self, mock_findAll):
        all_spells = [{'id': 1, 'name': 'spell1'}, {'id': 2, 'name': 'spell2'}]
        mock_findAll.return_value = [s['name'] for s in all_spells]

        for spell in all_spells:
            spell_by_name = self.dao.findByName(spell['name'])
            self.assertIsNotNone(spell_by_name)
            self.assertEqual(spell['id'], spell_by_name.id)
            self.assertEqual(spell['name'], spell_by_name.name)

if __name__ == '__main__':
    unittest.main()
