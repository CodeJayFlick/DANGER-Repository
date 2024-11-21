import unittest
from unittest.mock import patch, MagicMock

class PartyImplTest(unittest.TestCase):
    def test_party_action(self):
        party_member1 = MagicMock()
        party_member2 = MagicMock()

        party = PartyImpl()
        party.add_member(party_member1)
        party.add_member(party_member2)

        party_member1.assert_called_once_with('joinedParty', party)
        party_member2.assert_called_once_with('joinedParty', party)

        party.party_action(party_member1, 'GOLD')
        self.assertEqual(0, party_member1.call_count)  # verify no more interactions
        party_member2.assert_called_once_with('partyAction', 'GOLD')

    def setUp(self):
        pass

if __name__ == '__main__':
    unittest.main()
