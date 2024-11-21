import unittest
from unittest.mock import patch, MagicMock

class HayesTest(unittest.TestCase):

    @patch('com.iluwatar.acyclicvisitor.ConfigureForDosVisitor')
    def test_accept_for_dos(self, mock_configure_for_dos_visitor):
        hayes = Hayes()
        visitor = MagicMock(spec=ConfigureForDosVisitor)
        
        hayes.accept(visitor)

        visitor.visit.assert_called_once_with(hayes)

    @patch('com.iluwatar.acyclicvisitor.ConfigureForUnixVisitor')
    def test_accept_for_unix(self, mock_configure_for_unix_visitor):
        hayes = Hayes()
        visitor = MagicMock(spec=ConfigureForUnixVisitor)
        
        hayes.accept(visitor)

        self.assertEqual(0, visitor.visit.call_count)


if __name__ == '__main__':
    unittest.main()
