import unittest
from unittest.mock import patch, Mock


class FilterManager:
    def __init__(self):
        self.filters = []

    def filter_request(self, order):
        for f in self.filters:
            return f.execute(order)
        return "RUNNING..."



@patch('com.iluwatar.intercepting.filter.Filter')
class TestFilterManager(unittest.TestCase):

    @patch('com.iluwatar.intercepting.filter.Order')
    def test_filter_request(self, mock_order: Mock):
        target = Mock()
        filter_manager = FilterManager()

        self.assertEqual("RUNNING...", filter_manager.filter_request(mock_order))
        target.assert_not_called()

    @patch('com.iluwatar.intercepting.filter.Order')
    def test_add_filter(self, mock_order: Mock):
        target = Mock()
        filter_manager = FilterManager()

        target.assert_not_called()

        filter_mock = Mock(return_value="filter")
        filter_manager.addFilter(filter_mock)

        order = mock_order
        self.assertEqual("filter", filter_manager.filter_request(order))
        filter_mock.assert_called_once_with(order)
        target.assert_not_called()


if __name__ == '__main__':
    unittest.main()
