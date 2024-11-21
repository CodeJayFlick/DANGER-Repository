class BorrowerRole:
    def __init__(self):
        self.name = None

    def set_name(self, name: str) -> None:
        self.name = name

    def borrow(self) -> str:
        if not self.name:
            return "Borrower wants to get some money."
        else:
            return f"Borrower {self.name} wants to get some money."


import unittest
from unittest.mock import patch, Mock

class TestBorrowerRole(unittest.TestCase):

    @patch('builtins.print')
    def test_borrow(self, mock_print):
        borrower_role = BorrowerRole()
        borrower_role.set_name("test")
        self.assertEqual(borrower_role.borrow(), "Borrower test wants to get some money.")


if __name__ == '__main__':
    unittest.main()
