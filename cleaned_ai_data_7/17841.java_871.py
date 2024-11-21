import mysql.connector
from unittest import TestCase


class IoTDBInsertMultiRowIT(TestCase):
    sqls = []
    connection = None

    def setUpClass(cls):
        cls.sqls.append("SET STORAGE GROUP TO root.t1")
        cls.sqls.append(
            "CREATE TIMESERIES root.t1.wf01.wt01.status WITH DATATYPE=BOOLEAN, ENCODING=PLAIN"
        )
        cls.sqls.append(
            "CREATE TIMESERIES root.t1.wf01.wt01.temperature WITH DATATYPE=FLOAT, ENCODING=RLE"
        )

    def tearDownClass(cls):
        if cls.connection:
            try:
                cls.connection.close()
            except Exception as e:
                print(str(e))

    @classmethod
    def setUp(cls):
        import mysql.connector

        cls.sqls = []
        cls.connection = mysql.connector.connect(
            host="127.0.0.1", port=6667, user="root", password="root"
        )
        statement = cls.connection.cursor()

        for sql in cls.sqls:
            statement.execute(sql)

    @classmethod
    def tearDown(cls):
        if cls.connection:
            try:
                cls.connection.close()
            except Exception as e:
                print(str(e))

    def testInsertMultiRow(self):
        st0 = self.connection.cursor()
        st0.execute("insert into root.t1.wf01.wt01(timestamp, status) values (1, true)")
        st0.execute(
            "insert into root.t1.wf01.wt01(timestamp, status) values (2, true),(3, false)"
        )
        st0.execute(
            "insert into root.t1.wf01.wt01(timestamp, status) values (4, true),(5, true),(6, false)"
        )

        st0.execute(
            "insert into root.t1.wf01.wt01(timestamp, temperature, status) values (7, 15.3, true)"
        )
        st0.execute(
            "insert into root.t1.wf01.wt01(timestamp, temperature, status) values (8, 18.3, false),(9, 23.1, false)"
        )
        st0.execute(
            "insert into root.t1.wf01.wt01(timestamp, temperature, status) values (10, 22.3, true),(11, 18.8, false),(12, 24.4, true)"
        )

        st0.close()

    def testInsertWithTimesColumns(self):
        try:
            st1 = self.connection.cursor()
            st1.execute("insert into root.t1.wf01.wt01(timestamp) values(1)")
        except Exception as e:
            pass
