import mysql.connector
from unittest import TestCase

class IoTDBDeletionIT(TestCase):
    creation_sqls = [
        "SET STORAGE GROUP TO root.vehicle.d0",
        "CREATE TIMESERIES root.vehicle.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE",
        "CREATE TIMESERIES root.vehicle.d0.s1 WITH DATATYPE=INT64, ENCODING=RLE",
        "CREATE TIMESERIES root.vehicle.d0.s2 WITH DATATYPE FLOAT, ENCODING=RLE",
        "CREATE TIMESERIES root.vehicle.d0.s3 WITH DATATYPE TEXT, ENCODING=PLAIN",
        "CREATE TIMESERIES root.vehicle.d0.s4 WITH DATATYPE BOOLEAN, ENCODING=PLAIN"
    ]

    insert_template = "INSERT INTO root.vehicle.d0(timestamp,s0,s1,s2,s3,s4) VALUES(%d,%d,%d,%f,'%s',%b)"

    delete_all_template = "DELETE FROM root.vehicle.d0 WHERE time <= 10000"

    def setUp(self):
        self.cnx = mysql.connector.connect(
            user='root',
            password='root',
            host='127.0.0.1',
            port=6667,
            database='iotdb'
        )
        self.cursor = self.cnx.cursor()
        for sql in self.creation_sqls:
            self.cursor.execute(sql)
        prepare_series()

    def tearDown(self):
        clean_data()
        self.cursor.close()
        self.cnx.close()

    @staticmethod
    def testUnsupportedValueFilter():
        try:
            self.cursor.execute("insert into root.vehicle.d0(time,s0) values (10,310)")
            self.cursor.execute("insert into root.vehicle.d0(time,s3) values (10,'text')")
            self.cursor.execute("insert into root.vehicle.d0(time,s4) values (10,true)")

            try:
                self.cursor.execute(
                    "DELETE FROM root.vehicle.d0.s0 WHERE s0 <= 300 AND time > 0 AND time < 100"
                )
                fail("should not reach here!")
            except mysql.connector.Error as e:
                assert e.msg == "303: Check metadata error: For delete statement, where clause can only contain atomic expressions like : time > XXX, time <= XXX, or two atomic expressions connected by 'AND'"

            try:
                self.cursor.execute(
                    "DELETE FROM root.vehicle.d0.s0 WHERE s0 <= 300 AND s0 > 0"
                )
                fail("should not reach here!")
            except mysql.connector.Error as e:
                assert e.msg == "303: Check metadata error: For delete statement, where clause can only contain atomic expressions like : time > XXX, time <= XXX, or two atomic expressions connected by 'AND'"

            try:
                self.cursor.execute(
                    "DELETE FROM root.vehicle.d0.s3 WHERE s3 = 'text'"
                )
                fail("should not reach here!")
            except mysql.connector.Error as e:
                assert e.msg == "303: Check metadata error: For delete statement, where clause can only contain atomic expressions like : time > XXX, time <= XXX, or two atomic expressions connected by 'AND'"

            try:
                self.cursor.execute(
                    "DELETE FROM root.vehicle.d0.s4 WHERE s4 != true"
                )
                fail("should not reach here!")
            except mysql.connector.Error as e:
                assert e.msg == "303: Check metadata error: For delete statement, where clause can only contain atomic expressions like : time > XXX, time <= XXX, or two atomic expressions connected by 'AND'"

        finally:
            self.cursor.execute("SELECT s0 FROM root.vehicle.d0")
            cnt = 1
            while True:
                row = self.cursor.fetchone()
                if not row:
                    break
                cnt += 1

    @staticmethod
    def test():
        prepare_data()

        try:
            self.cursor.execute(
                "DELETE FROM root.vehicle.d0.s0 WHERE time <= 300"
            )
            self.cursor.execute(
                "DELETE FROM root.vehicle.d0.** WHERE time > 50 and time <= 250"
            )

            self.cursor.execute("SELECT * FROM root.vehicle.d0")
            cnt = 1
            while True:
                row = self.cursor.fetchone()
                if not row:
                    break
                cnt += 1

        finally:
            clean_data()

    @staticmethod
    def testMerge():
        prepare_merge()

        try:
            self.cursor.execute("merge")

            before_flushing = self.cursor.execute(
                "SELECT * FROM root.vehicle.d0"
            )
            cnt = 1
            while True:
                row = before_flushing.fetchone()
                if not row:
                    break
                cnt += 1

            after_flushing = self.cursor.execute(
                "SELECT * FROM root.vehicle.d0"
            )
            cnt = 1
            while True:
                row = after_flushing.fetchone()
                if not row:
                    break
                cnt += 1

        finally:
            clean_data()

    @staticmethod
    def testDelAfterFlush():
        try:
            self.cursor.execute("SET STORAGE GROUP TO root.ln.wf01.wt01")
            self.cursor.execute(
                "CREATE TIMESERIES root.ln wf01 wt01.status WITH DATATYPE=BOOLEAN, ENCODING=PLAIN"
            )
            self.cursor.execute(
                f"INSERT INTO root.ln wf01 wt01(timestamp,status) VALUES(1509465600000,true)"
            )

            self.cursor.execute(f"INSERT INTO root.ln wf01 wt01(timestamp,status) VALUES(NOW(), false)")

            try:
                self.cursor.execute("delete from root.ln wf01 wt01.status where time <= NOW()")
                fail("should not reach here!")
            except mysql.connector.Error as e:
                assert e.msg == "303: Check metadata error: For delete statement, where clause can only contain atomic expressions like : time > XXX, time <= XXX, or two atomic expressions connected by 'AND'"

        finally:
            self.cursor.close()
            self.cnx.close()

    @staticmethod
    def testRangeDelete():
        prepare_data()

        try:
            self.cursor.execute("DELETE FROM root.vehicle.d0.* WHERE time <= 300 and time > 150")
            self.cursor.execute(
                "SELECT s0 FROM root.vehicle.d0"
            )
            cnt = 1
            while True:
                row = self.cursor.fetchone()
                if not row:
                    break
                cnt += 1

        finally:
            clean_data()

    @staticmethod
    def testFullDeleteWithoutWhereClause():
        try:
            self.cursor.execute("DELETE FROM root.vehicle.d0.s0")
            self.cursor.execute(
                "SELECT s0 FROM root.vehicle.d0"
            )
            cnt = 1
            while True:
                row = self.cursor.fetchone()
                if not row:
                    break
                cnt += 1

        finally:
            clean_data()

    @staticmethod
    def testPartialPathRangeDelete():
        prepare_data()

        try:
            self.cursor.execute("DELETE FROM root.vehicle.d0.* WHERE time > 50 and time <= 250")
            self.cursor.execute(
                "SELECT s0 FROM root.vehicle.d0"
            )
            cnt = 1
            while True:
                row = self.cursor.fetchone()
                if not row:
                    break
                cnt += 1

        finally:
            clean_data()

    @staticmethod
    def testDelSeriesWithSpecialSymbol():
        try:
            self.cursor.execute(
                "CREATE TIMESERIES root.ln.d1.\"status,01\" WITH DATATYPE=BOOLEAN, ENCODING=PLAIN"
            )
            self.cursor.execute(f"INSERT INTO root.ln d1(timestamp,\"status,01\") VALUES(300,true)")

            self.cursor.execute(f"SELECT \"status,01\" FROM root.ln d1")
            cnt = 2
            while True:
                row = self.cursor.fetchone()
                if not row:
                    break
                cnt += 1

        finally:
            try:
                self.cursor.execute("DELETE FROM root.ln d1.\"status,01\" WHERE time <= 400")
                fail("should not reach here!")
            except mysql.connector.Error as e:
                assert e.msg == "303: Check metadata error: For delete statement, where clause can only contain atomic expressions like : time > XXX, time <= XXX, or two atomic expressions connected by 'AND'"

        try:
            self.cursor.execute("DELETE FROM root.ln d1.\"status,01\"")
            fail("should not reach here!")
        except mysql.connector.Error as e:
            assert e.msg == "303: Check metadata error: For delete statement, where clause can only contain atomic expressions like : time > XXX, time <= XXX, or two atomic expressions connected by 'AND'"

    @staticmethod
    def prepare_series():
        for sql in IoTDBDeletionIT.creation_sqls:
            self.cursor.execute(sql)

    @staticmethod
    def clean_data():
        try:
            self.cursor.execute(IoTDBDeletionIT.delete_all_template)
        except mysql.connector.Error as e:
            print(e.msg)

    @staticmethod
    def prepare_merge():
        for i in range(10001, 20000):
            self.cursor.execute(
                IoTDBDeletionIT.insert_template % (i, i, i, float(i), f"'{i}'", i % 2 == 0)
            )

        for i in range(1, 10000):
            self.cursor.execute(
                IoTDBDeletionIT.insert_template % (i, i, i, float(i), f"'{i}'", i % 2 == 0)
            )
