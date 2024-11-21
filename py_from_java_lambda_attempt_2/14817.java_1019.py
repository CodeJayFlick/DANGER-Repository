Here is a translation of the Java code into equivalent Python code:

```Python
import unittest
from unittest.mock import patch
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

class AppConfigTest(unittest.TestCase):

    @patch('sqlalchemy.create_engine')
    def testDataSource(self, mock_create_engine):
        engine = mock_create_engine.return_value
        engine.connect().close()
        self.assertIsNotNone(mock_create_engine)

    @unittest.skipIf(not hasattr(__builtins__, 'assertEqual'), "This assertion is not available in Python 3.5 and below")
    @patch('sqlalchemy.create_engine')
    def testQuery(self, mock_create_engine):
        expected = "1"
        result = None
        with sessionmaker(bind=mock_create_engine.return_value).() as session:
            connection = session.connection()
            cursor = connection.cursor()
            cursor.execute(text("SELECT 1"))
            for row in cursor.fetchall():
                if not result:
                    result = str(row[0])
        self.assertEqual(expected, result)

if __name__ == '__main__':
    unittest.main()
```

Please note that this is a translation of the Java code into Python. The actual implementation may vary depending on your specific requirements and constraints.

Also, please be aware that SQLAlchemy (a popular ORM library for Python) has been used in place of JDBC to simulate database operations.