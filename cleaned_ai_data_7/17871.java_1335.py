import mysql.connector
from typing import List

class IoTDBResultSetIT:
    sqls: List[str] = []
    connection: object = None

    def setUp(self):
        self.close_stat_monitor()
        self.init_create_sql_statement()
        self.env_set_up()
        self.insert_data()

    def tearDown(self):
        self.close()
        self.clean_env()

    def close(self):
        if self.connection:
            try:
                self.connection.close()
            except Exception as e:
                print(str(e))

    def init_create_sql_statement(self):
        self.sqls.append("SET STORAGE GROUP TO root.t1")
        self.sqls.append(
            "CREATE TIMESERIES root.t1.wf01.wt01.status WITH DATATYPE=BOOLEAN, ENCODING=PLAIN"
        )
        self.sqls.append(
            "CREATE TIMESERIES root.t1.wf01.wt01.temperature WITH DATATYPE=FLOAT, ENCODING=RLE"
        )
        self.sqls.append(
            "CREATE TIMESERIES root.t1.wf01.wt01.type WITH DATATYPE=INT32, ENCODING=RLE"
        )
        self.sqls.append(
            "CREATE TIMESERIES root.t1.wf01.wt01.grade WITH DATATYPE=INT64, ENCODING=RLE"
        )

    def insert_data(self):
        try:
            cnx = mysql.connector.connect(
                user="root",
                password="root",
                host="127.0.0.1",
                port=6667,
                database="iotdb",
            )
            self.connection = cnx.cursor()
            for sql in self.sqls:
                self.connection.execute(sql)
        except Exception as e:
            print(str(e))

    def test_int_and_long_conversion(self):
        try:
            st0 = self.connection
            st0.execute(
                "insert into root.t1.wf01.wt01(timestamp, status, type, grade) values (1000, true, 1, 1000)"
            )
            st0.execute(
                "insert into root.t1.wf01.wt01(timestamp, status, type, grade) values (2000, false, 2, 2000)"
            )

            st1 = self.connection
            rs1 = st1.execute("select count(status) from root.t1 wf01 wt01")
            rs1.fetchone()
            # type of r1 is INT64(long), test long convert to int
            count_status = rs1[0]
            assert count_status == 2

            rs2 = st1.execute(
                "select type from root.t1.wf01.wt01 where time=1000 limit 1"
            )
            rs2.fetchone()
            # type of r2 is INT32(int), test int convert to long
            type_ = rs2[0]
            assert type_ == 1

            rs3 = st1.execute(
                "select grade from root.t1.wf01.wt01 where time=1000 limit 1"
            )
            rs3.fetchone()
            # type of r3 is INT64(long), test long convert to int
            grade = rs3[0]
            assert grade == 1000

        except Exception as e:
            print(str(e))
