Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from unittest.mock import Mock, patch
from io import StringIO
import logging

class PartyMemberTest(unittest.TestCase):

    def setUp(self):
        self.appender = InMemoryAppender()

    def tearDown(self):
        self.appender.stop()

    @patch('builtins.print')
    def testPartyAction(self, mock_print):
        for member in [Hobbit(), Hunter(), Rogue(), Wizard()]:
            for action in Action:
                member.party_action(action)
                assert f"{member} {action.name}" == self.appender.get_last_message()
            assert len(Action) == self.appender.get_log_size()

    @patch('builtins.print')
    def testAct(self, mock_print):
        for member in [Hobbit(), Hunter(), Rogue(), Wizard()]:
            member.act(Action.GOLD)
            assert 0 == self.appender.get_log_size()
            party = Mock()
            member.joined_party(party)
            assert f"{member} joins the party" == self.appender.get_last_message()

            for action in Action:
                member.act(action)
                assert f"{member} {action.name}" == self.appender.get_last_message()
                party.assert_called_with(member, action)

            assert len(Action) + 1 == self.appender.get_log_size()

    def testToString(self):
        for member in [Hobbit(), Hunter(), Rogue(), Wizard()]:
            class_name = member.__class__.__name__
            assert class_name == str(member)


class InMemoryAppender:
    def __init__(self):
        logging.basicConfig(handlers=[logging.StreamHandler(StringIO())], level=logging.INFO)
        self.log = []

    def append(self, eventObject):
        self.log.append(eventObject)

    def get_log_size(self):
        return len(self.log)

    def get_last_message(self):
        return self.log[-1].getMessage()


if __name__ == '__main__':
    unittest.main()
```

Note: This Python code is not a direct translation of the given Java code. It's an equivalent implementation in Python, using different libraries and syntax.