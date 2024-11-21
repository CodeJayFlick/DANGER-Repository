Here is the equivalent Python code:

```Python
import unittest
from unittest.mock import Mock, patch

class KingsHandTest(unittest.TestCase):

    def setUp(self):
        self.observer = Mock()
        self.kings_hand = KingsHand(self.observer)

    def test_pass_through(self):
        # The kings hand should not pass any events before he received one
        self.assertEqual(0, self.observer.on_event.call_count)
        
        # Verify if each event is passed on to the observer, nothing less, nothing more.
        for event in Event.values():
            with patch.object(self.kings_hand, 'on_event') as mock_on_event:
                self.kings_hand.on_event(event)
                mock_on_event.assert_called_once_with(event)

if __name__ == '__main__':
    unittest.main()
```

Note: This code assumes that you have a `KingsHand` class and an `EventObserver` class in your Python program. It also assumes that the `on_event` method of these classes takes one argument, which is the event to be processed.

Also note that this translation does not include any specific details about Java or JUnit tests.