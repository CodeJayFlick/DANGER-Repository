class CommanderTest:
    def __init__(self):
        pass  # equivalent to super().__init__()

    def verify_visit(self, unit: 'Commander', mocked_visitor) -> None:
        import unittest.mock as mockito
        from unittest import TestCase

        class UnitTest(TestCase):
            def setUp(self):
                self.commander = Commander()

            def test_verify_visit(self):
                with mockito.patch('unittest.mock') as m:
                    m.verify.assert_called_once_with(mocked_visitor, 'visitCommander', unit)

if __name__ == '__main__':
    unittest.main()
