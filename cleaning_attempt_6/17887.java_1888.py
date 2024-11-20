import pytz
from datetime import datetime
import unittest
from io import StringIO
from contextlib import redirect_stdout

class IoTDBTimeZoneIT(unittest.TestCase):

    def setUp(self):
        self.insert_sqls = [
            "SET STORAGE GROUP TO root.timezone",
            "CREATE TIMESERIES root.timezone.tz1 WITH DATATYPE  = INT32, ENCODING  = PLAIN"
        ]
        for sql in self.insert_sqls:
            with open('iotdb.sql', 'w') as f:
                f.write(sql + ';')
            import subprocess
            proc = subprocess.Popen(['mysql-connector-python', '-h127.0.0.1', '-P6667', '-uroot', '-proot'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            output, error = proc.communicate(input=sql.encode('utf8'))
        self.timestamp_str = "Time"
        self.tz1 = "root.timezone.tz1"

    def tearDown(self):
        with open('iotdb.sql', 'w') as f:
            pass

    def test_timezone_test(self):

        connection = mysql.connector.connect(
            host='127.0.0.1',
            port=6667,
            user='root',
            password='root'
        )
        cursor = connection.cursor(prepared=True)

        insert_sql_template = "insert into root.timezone(timestamp,tz1) values(%s,%s)"
        tz_offset_08 = pytz.FixedOffset(480)
        tz_offset_09 = pytz.FixedOffset(540)
        tz_offset_almaty = pytz.FixedOffset(3600)

        cursor.execute(insert_sql_template % ("1514779200000", "1"))
        cursor.execute(insert_sql_template % (datetime.now(tz=tz_offset_08).isoformat(), "2"))
        cursor.execute(insert_sql_template % (datetime.now(tz=tz_offset_08).isoformat() + "+08:00", "3"))
        cursor.execute(insert_sql_template % (datetime.now(tz=tz_offset_09).isoformat() + "+09:00", "4"))

        tz_offset_09
        cursor.execute(insert_sql_template % ("1514789200000", "6"))
        cursor.execute(insert_sql_template % (datetime.now(tz=tz_offset_almaty).isoformat(), "7"))
        cursor.execute(insert_sql_template % (datetime.now(tz=tz_offset_08).isoformat() + "+08:00", "8"))

        tz_offset_almaty
        cursor.execute(insert_sql_template % ("1514782807000", "10"))
        cursor.execute(insert_sql_template % (datetime.now(tz=tz_offset_almaty).isoformat(), "11"))
        cursor.execute(insert_sql_template % (datetime.now(tz=tz_offset_08).isoformat() + "+08:00", "12"))

        has_result_set = True
        try:
            cursor.execute("select * from root.")
        except mysql.connector.Error as e:
            self.fail(str(e))

        result_set = cursor.fetchall()
        cnt = 0
        for row in result_set:
            ans = str(row[0]) + "," + str(row[1])
            self.assertEqual(ret_array[cnt], ans)
            cnt += 1

        self.assertEqual(13, cnt)

    def test_create_timeseries(self):
        connection = mysql.connector.connect(
            host='127.0.0.1',
            port=6667,
            user='root',
            password='root'
        )
        cursor = connection.cursor(prepared=True)
        for sql in insert_sqls:
            try:
                cursor.execute(sql)
            except mysql.connector.Error as e:
                self.fail(str(e))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()

if __name__ == '__main__':
    unittest.main()
