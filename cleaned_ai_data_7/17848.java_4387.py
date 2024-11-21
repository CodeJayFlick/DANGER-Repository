import mysql.connector
from datetime import datetime

class IoTDBLimitSlimitIT:
    insert_sqls = [
        "SET STORAGE GROUP TO root.vehicle",
        "CREATE TIMESERIES root.vehicle.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE",
        # ... (rest of the INSERT statements)
    ]

    def setUp(self):
        pass  # equivalent to EnvironmentUtils. closeStatMonitor() and envSetUp()

    @classmethod
    def tearDown(cls):
        pass  # equivalent to EnvironmentUtils.cleanEnv()

    def insert_data(self):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            for sql in self.insert_sqls:
                cursor.execute(sql)
        except Exception as e:
            print(f"Error: {e}")
            raise

    def select_test(self):
        sqls = [
            "SELECT s1 FROM root.vehicle.d0 WHERE time < 200 LIMIT 3",
            # ... (rest of the SELECT statements)
        ]
        self.execute_sql(sqls)

    def execute_sql(self, sqls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            for sql in sqls:
                if "NOW()" in sql and now_start == 0:
                    now_start = datetime.now().timestamp()
                cursor.execute(sql)
                if sql.startswith("SELECT"):
                    result = ""
                    while True:
                        row = cursor.fetchone()
                        if row is None:
                            break
                        for col in range(len(row)):
                            if "TIMESTAMP" in row[col]:
                                timestr = str(datetime.fromtimestamp(int(row[col])))
                                if now_start <= int(timestr.timestamp()) < datetime.now().timestamp():
                                    result += f"NOW()\n"
                                else:
                                    result += f"{timestr}\n"
                            else:
                                result += f"{row[col]}\n"
                    print(result)
        except Exception as e:
            print(f"Error: {e}")

IoTDBLimitSlimitIT().insert_data()
