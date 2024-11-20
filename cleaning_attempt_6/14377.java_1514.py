import unittest
from pymongo import MongoClient
from datetime import datetime

class MongoEventLogTest(unittest.TestCase):

    TEST_DB = "lotteryDBTest"
    TEST_EVENTS_COLLECTION = "testEvents"

    def setUp(self):
        self.mongo_client = MongoClient()
        self.mongo_client.drop_database(TEST_DB)
        self.mongo_event_log = MongoEventLog(TEST_DB, TEST_EVENTS_COLLECTION)

    def test_setup(self):
        self.assertEqual(0, self.mongo_event_log.get_events_collection().count())

    def test_fund_transfers(self):
        player_details = {"email": "john@wayne.com", "phone_number": "03432534543"}
        for _ in range(5):
            self.mongo_event_log.prize_error(player_details, 1000)
            self.assertEqual(self.mongo_event_log.get_events_collection().count(), _ + 1)

    def test_ticket_transfers(self):
        player_details = {"email": "john@wayne.com", "phone_number": "03432534543"}
        for _ in range(5):
            self.mongo_event_log.ticket_submit_error(player_details)
            self.assertEqual(self.mongo_event_log.get_events_collection().count(), _ + 1)

    def test_ticket_won_transfers(self):
        player_details = {"email": "john@wayne.com", "phone_number": "03432534543"}
        for _ in range(5):
            self.mongo_event_log.ticket_won(player_details, 1000)
            self.assertEqual(self.mongo_event_log.get_events_collection().count(), _ + 1)

if __name__ == '__main__':
    unittest.main()
