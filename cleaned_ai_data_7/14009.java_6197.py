class CustomerDto:
    def __init__(self, id: str, first_name: str, last_name: str):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name


class CustomerResource:
    def __init__(self, customers=None):
        if not customers:
            self.customers = []
        else:
            self.customers = customers

    def get_all_customers(self) -> list:
        return self.customers[:]

    def save(self, customer: dict):
        self.customers.append(customer)

    def delete(self, id: str):
        for customer in self.customers:
            if customer['id'] == id:
                self.customers.remove(customer)
                break


import unittest

class TestCustomerResource(unittest.TestCase):

    def test_get_all_customers(self):
        customers = [dict(id='1', first_name="Melody", last_name="Yates")]
        resource = CustomerResource(customers)
        all_customers = resource.get_all_customers()
        self.assertEqual(1, len(all_customers))
        self.assertEqual("1", all_customers[0]['id'])
        self.assertEqual("Melody", all_customers[0]['first_name'])
        self.assertEqual("Yates", all_customers[0]['last_name'])

    def test_save_customer(self):
        customer = dict(id='1', first_name="Rita", last_name="Reynolds")
        resource = CustomerResource()
        resource.save(customer)
        all_customers = resource.get_all_customers()
        self.assertEqual(1, len(all_customers))
        self.assertEqual("1", all_customers[0]['id'])
        self.assertEqual("Rita", all_customers[0]['first_name'])
        self.assertEqual("Reynolds", all_customers[0]['last_name'])

    def test_delete_customer(self):
        customer = dict(id='1', first_name="Terry", last_name="Nguyen")
        customers = [customer]
        resource = CustomerResource(customers)
        resource.delete('1')
        all_customers = resource.get_all_customers()
        self.assertTrue(len(all_customers) == 0)


if __name__ == '__main__':
    unittest.main()
