import mysql.connector
from datetime import datetime

class IoTDBRecoverIT:
    TIMESTAMP_STR = "Time"
    TEMPERATURE_STR = "root.ln.wf01.wt01.temperature"

    creation_sqls = [
        "SET STORAGE GROUP TO root.vehicle.d0",
        "SET STORAGE GROUP TO root.vehicle.d1",
        "CREATE TIMESERIES root.vehicle.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE",
        "CREATE TIMESERIES root.vehicle.d0.s1 WITH DATATYPE=INT64, ENCODING=RLE",
        "CREATE TIMESERIES root.vehicle.d0.s2 WITH DATATYPE=FLOAT, ENCODING=RLE",
        "CREATE TIMESERIES root.vehicle.d0.s3 WITH DATATYPE=TEXT, ENCODING=PLAIN",
        "CREATE TIMESERIES root.vehicle.d0.s4 WITH DATATYPE=BOOLEAN, ENCODING=PLAIN"
    ]

    data_set2 = [
        "SET STORAGE GROUP TO root.ln.wf01.wt01",
        "CREATE TIMESERIES root.ln wf01 wt01.status WITH DATATYPE=BOOLEAN, ENCODING=PLAIN",
        "CREATE TIMESERIES root.ln wf01 wt01.temperature WITH DATATYPE=FLOAT, ENCODING=PLAIN",
        "CREATE TIMESERIES root.ln wf01 wt01.hardware WITH DATATYPE=INT32, ENCODING=PLAIN",
        "INSERT INTO root.ln.wf01.wt01(timestamp,temperature,status,hardware) VALUES(1, 1.1, false, 11)",
        "INSERT INTO root.ln.wf01.wt01(timestamp,temperature,status,hardware) VALUES(2, 2.2, true, 22)",
        "INSERT INTO root.ln wf01 wt01(timestamp,temperature,status,hardware) VALUES(3, 3.3, false, 33 )",
        "INSERT INTO root.ln wf01 wt01(timestamp,temperature,status,hardware) VALUES(4, 4.4, false, 44)",
        "INSERT INTO root.ln wf01 wt01(timestamp,temperature,status,hardware) VALUES(5, 5.5, false, 55)"
    ]

    d0s0 = "root.vehicle.d0.s0"
    d0s1 = "root.vehicle.d0.s1"
    d0s2 = "root.vehicle.d0.s2"
    d0s3 = "root.vehicle.d0.s3"

    insert_template = "INSERT INTO root.vehicle.d0(timestamp,s0,s1,s2,s3) VALUES(%d,%d,%d,%f,%s)"

    def setUp(self):
        self.cnx = mysql.connector.connect(
            user='root',
            password='root',
            host='127.0.0.1',
            port=6667,
            database='iotdb'
        )
        cursor = self.cnx.cursor()
        for sql in creation_sqls:
            cursor.execute(sql)
        for sql in data_set2:
            cursor.execute(sql)

    def tearDown(self):
        self.cnx.close()

    def mergeTest(self):
        ret_array = ["0,2", "0,4", "0,3"]
        try:
            with self.cnx.cursor() as cursor:
                has_resultset = cursor.execute("select count(temperature) from root.ln.wf01.wt01 where time > 3")
                assert has_resultset
                cnt = 0
                for row in cursor.fetchall():
                    ans = str(row[0]) + "," + str(row[1])
                    assert ret_array[cnt] == ans
                    cnt += 1

            with self.cnx.cursor() as cursor:
                has_resultset = cursor.execute("select min_ time(temperature) from root.ln.wf01.wt01 where time > 3")
                assert has_resultset
                for row in cursor.fetchall():
                    ans = str(row[0]) + "," + str(row[1])
                    assert ret_array[cnt] == ans
                    cnt += 1

            with self.cnx.cursor() as cursor:
                has_resultset = cursor.execute("select min_ time(temperature) from root.ln.wf01.wt01 where temperature > 3")
                assert has_resultset
                for row in cursor.fetchall():
                    ans = str(row[0]) + "," + str(row[1])
                    assert ret_array[cnt] == ans
                    cnt += 1

        except Exception as e:
            print(e)

    def vmTest(self):
        try:
            with self.cnx.cursor() as cursor:
                for i in range(2000, 2500):
                    cursor.execute(insert_template % (i, i, i, float(i), "'" + str(i) + "'", "false"))
                cursor.execute("flush")

            # we want to recover
            EnvironmentUtils.stopDaemon()
            time.sleep(1000)
            EnvironmentUtils.activeDaemon()

        except Exception as e:
            print(e)

    def prepareData(self):
        try:
            with self.cnx.cursor() as cursor:
                for sql in creation_sqls:
                    cursor.execute(sql)

                for sql in data_set2:
                    cursor.execute(sql)

                # prepare BufferWrite file
                for i in range(5000, 7000):
                    cursor.execute(insert_template % (i, i, i, float(i), "'" + str(i) + "'", "true"))
                cursor.execute("flush")
                for i in range(7500, 8500):
                    cursor.execute(insert_template % (i, i, i, float(i), "'" + str(i) + "'", "false"))
                cursor.execute("flush")

        except Exception as e:
            print(e)

if __name__ == "__main__":
    IoTDBRecoverIT().setUp()
