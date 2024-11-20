import unittest
from unittest.mock import patch, mock_open, ANY
from time import sleep

class ProducerTest(unittest.TestCase):

    @patch('queue.Queue')
    def test_produce(self, queue):
        with patch('time.sleep', return_value=None) as mocked_sleep:
            producer = Producer("producer", queue)
            producer.produce()
            queue.put.assert_called_once_with(ANY)

if __name__ == '__main__':
    unittest.main()
