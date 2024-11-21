import unittest
from unittest.mock import Mock, patch


class ServantTest(unittest.TestCase):

    @patch('royalty.Royalty')
    def test_feed(self, mock_royalty):
        royalty = Mock()
        servant = Servant("test")
        servant.feed(royalty)
        royalty.get_fed.assert_called_once()

    @patch('royalty.Royalty')
    def test_give_wine(self, mock_royalty):
        royalty = Mock()
        servant = Servant("test")
        servant.give_wine(royalty)
        royalty.get_drink.assert_called_once()

    @patch('royalty.Royalty')
    def test_give_compliments(self, mock_royalty):
        royalty = Mock()
        servant = Servant("test")
        servant.give_compliments(royalty)
        royalty.receive_compliments.assert_called_once()

    def test_check_if_you_will_be_hanged(self):
        good_mood_royalties = [Mock() for _ in range(3)]
        bad_mood_royalties = [good_mood_royalties[0], good_mood_royalties[1], Mock()]

        for royalty in good_mood_royalties:
            royalty.get_mood.return_value = True

        for royalty in bad_mood_royalties:
            royalty.get_mood.return_value = True

        self.assertTrue(Servant("test").check_if_you_will_be_hanged(good_mood_royalties))
        self.assertTrue(Servant("test").check_if_you_will_be_hanged(bad_mood_royalties))


if __name__ == '__main__':
    unittest.main()
