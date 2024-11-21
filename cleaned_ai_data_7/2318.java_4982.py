import unittest
from unittest.mock import patch

class TestPathUtils(unittest.TestCase):

    @patch('pathutils.parse')
    def test_parse_empty(self, mock_parse):
        self.assertEqual(mock_parse.return_value, [])

    @patch('pathutils.parse')
    def test_parse_name(self, mock_parse):
        mock_parse.return_value = ['name']
        self.assertEqual(pathutils.parse("name"), ['name'])

    @patch('pathutils.parse')
    def test_parse_dotted_name(self, mock_parse):
        mock_parse.return_value = ['name']
        self.assertEqual(pathutils.parse(".name"), ['name'])

    @patch('pathutils.parse')
    def test_parse_index(self, mock_parse):
        mock_parse.return_value = ['[index]']
        self.assertEqual(pathutils.parse("[index]"), ['[index]'])

    @patch('pathutils.parse')
    def test_parse_name_then_index(self, mock_parse):
        mock_parse.return_value = ['name', '[index]']
        self.assertEqual(pathutils.parse("name[index]"), ['name', '[index]'])

    @patch('pathutils.parse')
    def test_parse_index_then_name(self, mock_parse):
        mock_parse.return_value = ['[index]', 'name']
        self.assertEqual(pathutils.parse("[index].name"), ['[index]', 'name'])

    @patch('pathutils.parse')
    def test_parse_err_index_no_dot_name(self, mock_parse):
        with self.assertRaises(IllegalArgumentException):
            pathutils.parse("[index]name")

    @patch('pathutils.parse')
    def test_parse_name_then_name(self, mock_parse):
        mock_parse.return_value = ['n1', 'n2']
        self.assertEqual(pathutils.parse("n1.n2"), ['n1', 'n2'])

    @patch('pathutils.parse')
    def test_parse_index_then_index(self, mock_parse):
        mock_parse.return_value = ['[i1]', '[i2]']
        self.assertEqual(pathutils.parse("[i1][i2]"), ['[i1]', '[i2]'])

    @patch('pathutils.parse')
    def test_parse_index_with_dot(self, mock_parse):
        mock_parse.return_value = ['[index. more]']
        self.assertEqual(pathutils.parse("[index.more]"), ['[index. more]'])

    @patch('pathutils.parse')
    def test_parse_parenthesized_name_with_dot(self, mock_parse):
        mock_parse.return_value = ['query(e.x==6)']
        self.assertEqual(pathutils.parse(".query(e.x==6)"), ['query(e.x==6)'])
