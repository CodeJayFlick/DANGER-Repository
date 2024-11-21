class InMemoryCustomerDaoTest:
    def __init__(self):
        self.dao = None
        self.CUSTOMER = Customer(1, "Freddy", "Krueger")

    @classmethod
    def setUp(cls):
        cls.dao = InMemoryCustomerDao()
        assert cls.dao.add(cls.CUSTOMER)

    class NonExistingCustomer:
        @staticmethod
        def adding_should_result_in_success():
            all_customers = list(cls.dao.get_all())
            assert len(all_customers) == 1

            non_existing_customer = Customer(2, "Robert", "Englund")
            result = cls.dao.add(non_existing_customer)
            assert result

            assert len(list(cls.dao.get_all())) == 2
            assert cls.CUSTOMER in list(cls.dao.get_all())
            assert non_existing_customer in list(cls.dao.get_all())

        @staticmethod
        def deletion_should_be_failure_and_not_affect_existing_customers():
            non_existing_customer = Customer(2, "Robert", "Englund")
            result = cls.dao.delete(non_existing_customer)
            assert not result

            assert len(list(cls.dao.get_all())) == 1

        @staticmethod
        def updation_should_be_failure_and_not_affect_existing_customers():
            non_existing_id = get_non_existing_customer_id()
            new_first_name = "Douglas"
            new_last_name = "MacArthur"
            customer = Customer(non_existing_id, new_first_name, new_last_name)
            result = cls.dao.update(customer)

            assert not result
            assert not cls.CUSTOMER in list(cls.dao.get_all())

        @staticmethod
        def retrieve_should_return_no_customer():
            assert not cls.CUSTOMER in list(cls.dao.get_all())

    class ExistingCustomer:
        @staticmethod
        def adding_should_result_in_failure_and_not_affect_existing_customers():
            result = cls.dao.add(cls.CUSTOMER)
            assert not result

            assert len(list(cls.dao.get_all())) == 1
            assert cls.CUSTOMER in list(cls.dao.get_all())

        @staticmethod
        def deletion_should_be_success_and_customer_should_be_non_accessible():
            result = cls.dao.delete(cls.CUSTOMER)
            assert result

            assert len(list(cls.dao.get_all())) == 0
            assert not cls.CUSTOMER in list(cls.dao.get_all())

        @staticmethod
        def updation_should_be_success_and_accessing_the_same_customer_should_return_updated_information():
            new_first_name = "Bernard"
            new_last_name = "Montgomery"
            customer = Customer(cls.CUSTOMER.id, new_first_name, new_last_name)
            result = cls.dao.update(customer)

            assert result

            updated_customer = list(cls.dao.get_all())[0]
            assert updated_customer.first_name == new_first_name
            assert updated_customer.last_name == new_last_name

        @staticmethod
        def retrieve_should_return_the_customer():
            optional_customer = cls.CUSTOMER in list(cls dao.get_all())
            assert optional_customer and optional_customer[0] == cls.CUSTOMER


def get_non_existing_customer_id():
    return 999


class Customer:
    def __init__(self, id, first_name, last_name):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name

