import unittest
from logbook import Logger, Level, INFO
from collections import deque

class SpecialCasesTest(unittest.TestCase):

    def setUp(self):
        self.application_services = ApplicationServices()
        Db.seed_user("ignite1771", 1000.0)
        Db.seed_item("computer", 800.0)
        Db.seed_item("car", 20000.0)

    def test_down_for_maintenance(self):
        logger = Logger('DownForMaintenance')
        list_appender = deque()
        logger.push_application(list_appender, level=INFO)
        
        MaintenanceLock.set_lock(True)
        receipt = self.application_services.logged_in_user_purchase(None, None)
        receipt.show()

        logging_event_list = list(list_appender)
        self.assertEqual("Down for maintenance", logging_event_list[0].message)
        self.assertEqual(INFO, logging_event_list[0].level)

    def test_invalid_user(self):
        logger = Logger('InvalidUser')
        list_appender = deque()
        logger.push_application(list_appender, level=INFO)
        
        receipt = self.application_services.logged_in_user_purchase("a", None)
        receipt.show()

        logging_event_list = list(list_appender)
        self.assertEqual("Invalid user: a", logging_event_list[0].message)
        self.assertEqual(INFO, logging_event_list[0].level)

    def test_out_of_stock(self):
        logger = Logger('OutOfStock')
        list_appender = deque()
        logger.push_application(list_appender, level=INFO)
        
        receipt = self.application_services.logged_in_user_purchase("ignite1771", "tv")
        receipt.show()

        logging_event_list = list(list_appender)
        self.assertEqual("Out of stock: tv for user ignite1771 to buy",
                         logging_event_list[0].message)
        self.assertEqual(INFO, logging_event_list[0].level)

    def test_insufficient_funds(self):
        logger = Logger('InsufficientFunds')
        list_appender = deque()
        logger.push_application(list_appender, level=INFO)
        
        receipt = self.application_services.logged_in_user_purchase("ignite1771", "car")
        receipt.show()

        logging_event_list = list(list_appender)
        self.assertEqual("Insufficient funds: 1000.0 of user ignite1771 for buying item car",
                         logging_event_list[0].message)
        self.assertEqual(INFO, logging_event_list[0].level)

    def test_receipt_dto(self):
        logger = Logger('ReceiptDto')
        list_appender = deque()
        logger.push_application(list_appender, level=INFO)
        
        receipt = self.application_services.logged_in_user_purchase("ignite1771", "computer")
        receipt.show()

        logging_event_list = list(list_appener)
        self.assertEqual("Receipt: 800.0 paid",
                         logging_event_list[0].message)
        self.assertEqual(INFO, logging_event_list[0].level)

if __name__ == '__main__':
    unittest.main()
