import unittest

class Order:
    def __init__(self):
        self.name = None
        self.contact_number = None
        self.address = None
        self.deposit_number = None
        self.order_item = None

    def set_name(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def set_contact_number(self, contact_number):
        self.contact_number = contact_number

    def get_contact_number(self):
        return self.contact_number

    def set_address(self, address):
        self.address = address

    def get_address(self):
        return self.address

    def set_deposit_number(self, deposit_number):
        self.deposit_number = deposit_number

    def get_deposit_number(self):
        return self.deposit_number

    def set_order_item(self, order_item):
        self.order_item = order_item

    def get_order_item(self):
        return self.order_item


class TestOrder(unittest.TestCase):

    EXPECTED_VALUE = "test"

    @unittest.skip
    def test_set_name(self):
        order = Order()
        order.set_name(self.EXPECTED_VALUE)
        self.assertEqual(order.get_name(), self.EXPECTED_VALUE)

    @unittest.skip
    def test_set_contact_number(self):
        order = Order()
        order.set_contact_number(self.EXPECTED_VALUE)
        self.assertEqual(order.get_contact_number(), self.EXPECTED_VALUE)

    @unittest.skip
    def test_set_address(self):
        order = Order()
        order.set_address(self.EXPECTED_VALUE)
        self.assertEqual(order.get_address(), self.EXPECTED_VALUE)

    @unittest.skip
    def test_set_deposit_number(self):
        order = Order()
        order.set_deposit_number(self.EXPECTED_VALUE)
        self.assertEqual(order.get_deposit_number(), self.EXPECTED_VALUE)

    @unittest.skip
    def test_set_order_item(self):
        order = Order()
        order.set_order_item(self.EXPECTED_VALUE)
        self.assertEqual(order.get_order_item(), self.EXPECTED_VALUE)


if __name__ == '__main__':
    unittest.main()
