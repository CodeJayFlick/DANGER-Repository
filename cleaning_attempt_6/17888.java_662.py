import mysql.connector
from unittest import TestCase
import time


class IoTDBTracingIT(TestCase):

    def setUp(self):
        self.envSetUp()
        self.prepareData()

    def tearDown(self):
        self.cleanEnv()

    def envSetUp(self):
        pass  # This method is not implemented in the original code

    def cleanEnv(self):
        pass  # This method is not implemented in the original code

    def prepareData(self):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            cursor.execute("SET STORAGE GROUP TO root.sg_tracing")
            cursor.execute("CREATE TIMESERIES root.sg_tracing.d1.s1 WITH DATATYPE=INT32, ENCODING=RLE")

            insert_template = "INSERT INTO root.sg_tracing.d1(timestamp, s1) VALUES(%s,%s)"
            for i in range(100, 200):
                cursor.execute(insert_template % (i, i))
            cnx.commit()
            cursor.close()

        except Exception as e:
            print(str(e))

    def testTracing(self):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            cursor.execute("tracing select s1 from root.sg_tracing.d1")
            result_set = cursor.fetchall()

            self.assertTrue(result_set)
            self.assertEqual(len(result_set), 100)

        except Exception as e:
            print(str(e))
