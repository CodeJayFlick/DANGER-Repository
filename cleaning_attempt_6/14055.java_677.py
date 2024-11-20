import unittest
from datetime import date
from joda_money import Money, CurrencyUnit

class Customer:
    def __init__(self):
        self.name = None
        self.money = None
        self.customerDao = None

class Product:
    def __init__(self):
        self.name = None
        self.price = None
        self.expirationDate = None
        self.productDao = None

class CustomerDaoImpl:
    def __init__(self, dataSource):
        self.dataSource = dataSource

    def findByName(self, name):
        # TO DO: implement this method
        pass

    def save(self, customer):
        # TO DO: implement this method
        pass

    def update(self, customer):
        # TO DO: implement this method
        pass

class CustomerDaoImplTest(unittest.TestCase):

    INSERT_CUSTOMER_SQL = "insert into CUSTOMERS values('customer', 100)"
    SELECT_CUSTOMERS_SQL = "select name, money from CUSTOMERS"
    INSERT_PURCHASES_SQL = "insert into PURCHASES values('product', 'customer')"

    def setUp(self):
        # create db schema
        self.dataSource = TestUtils.createDataSource()

        TestUtils.deleteSchema(self.dataSource)
        TestUtils.createSchema(self.dataSource)

        # setup objects
        self.customerDao = CustomerDaoImpl(self.dataSource)

        customer = Customer()
        customer.name = "customer"
        customer.money = Money.of(CurrencyUnit.USD, 100.0)
        customer.customerDao = self.customerDao

        product = Product()
        product.name = "product"
        product.price = Money.of(USD, 100.0)
        product.expirationDate = date.fromisoformat("2021-06-27")
        product.productDao = CustomerDaoImpl(self.dataSource)

    def tearDown(self):
        TestUtils.deleteSchema(self.dataSource)

    @unittest.skip
    def test_find_customer_by_name(self):
        customer = self.customerDao.findByName("customer")

        self.assertTrue(customer.is_empty())

        TestUtils.executeSQL(INSERT_CUSTOMER_SQL, self.dataSource)
        customer = self.customerDao.findByName("customer")
        
        self.assertFalse(customer.is_empty())
        self.assertEqual("customer", customer.get().name)
        self.assertEqual(Money.of(CurrencyUnit.USD, 100), customer.get().money)

    @unittest.skip
    def test_save_customer(self):
        self.customerDao.save(customer)

        with self.dataSource.connection() as connection:
            statement = connection.createStatement()
            rs = statement.executeQuery(SELECT_CUSTOMERS_SQL)

            while rs.next():
                self.assertEqual("customer", rs.getString(1))
                self.assertEqual(Money.of(CurrencyUnit.USD, 100), Money.from_amount(rs.getBigDecimal(2).doubleValue(), USD))

        with self.assertRaises(SQLException):
            self.customerDao.save(customer)

    @unittest.skip
    def test_update_customer(self):
        TestUtils.executeSQL(INSERT_CUSTOMER_SQL, self.dataSource)
        
        customer.money = Money.of(CurrencyUnit.USD, 99)

        self.customerDao.update(customer)

        with self.dataSource.connection() as connection:
            statement = connection.createStatement()
            rs = statement.executeQuery(SELECT_CUSTOMERS_SQL)

            while rs.next():
                self.assertEqual("customer", rs.getString(1))
                self.assertEqual(Money.of(CurrencyUnit.USD, 99), Money.from_amount(rs.getBigDecimal(2).doubleValue(), USD))

    @unittest.skip
    def test_add_product_to_purchases(self):
        TestUtils.executeSQL(INSERT_CUSTOMER_SQL, self.dataSource)
        TestUtils.executeSQL(ProductDaoImplTest.INSERT_PRODUCT_SQL, self.dataSource)

        self.customerDao.addProduct(product, customer)

        with self.dataSource.connection() as connection:
            statement = connection.createStatement()
            rs = statement.executeQuery(SELECT_PURCHASES_SQL)

            while rs.next():
                self.assertEqual("product", rs.getString(1))
                self.assertEqual("customer", rs.getString(2))

    @unittest.skip
    def test_delete_product_from_purchases(self):
        TestUtils.executeSQL(INSERT_CUSTOMER_SQL, self.dataSource)
        TestUtils.executeSQL(ProductDaoImplTest.INSERT_PRODUCT_SQL, self.dataSource)
        TestUtils.executeSQL(INSERT_PURCHASES_SQL, self.dataSource)

        self.customerDao.deleteProduct(product, customer)

        with self.dataSource.connection() as connection:
            statement = connection.createStatement()
            rs = statement.executeQuery(SELECT_PURCHASES_SQL)

            while not rs.next():
                pass

if __name__ == '__main__':
    unittest.main()
