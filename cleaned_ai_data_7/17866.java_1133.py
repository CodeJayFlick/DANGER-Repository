import mysql.connector
from datetime import datetime as dt

class IoTDBQuotedPathIT:
    def setUp(self):
        pass  # No equivalent in Python for EnvironmentUtils.closeStatMonitor() or envSetUp()

    def tearDown(self):
        pass  # No equivalent in Python for cleanEnv()

    def test(self):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            
            # Create timeseries
            cursor.execute("CREATE TIMESERIES root.ln.wf01.wt01.status2_3 WITH DATATYPE=BOOLEAN, ENCODING=PLAIN")
            cursor.execute("INSERT INTO root.ln wf01 wt01 (timestamp,\"status.2.3\") values(%s, %s)", ("1509465600000", "true"))
            cursor.execute("INSERT INTO root.ln wf01 wt01 (timestamp,\"status.2.3\") values(%s, %s)", ("1509465600001", "true"))
            cursor.execute("INSERT INTO root.ln wf01 wt01 (timestamp,\"status.2.3\") values(%s, %s)", ("1509465600002", "false"))
            cursor.execute("INSERT INTO root.ln wf01 wt01 (timestamp,\"status.2.3\") values(%s, %s)", ("1509465600003", "false"))

            # Query timeseries
            cursor.execute("SELECT * FROM root.ln.wf01.wt01")
            result = cursor.fetchall()
            
            exp = ["1509465600000,true", "1509465600001,true", "1509465600002,false", "1509465600003,false"]
            for i, row in enumerate(result):
                assertEquals(exp[i], str(row[0]) + "," + str(row[1]))

            cursor.execute("SELECT * FROM root.ln.wf01.wt01 WHERE \"status.2.3\" = false")
            result = cursor.fetchall()
            
            exp = ["1509465600002,false", "1509465600003,false"]
            for i, row in enumerate(result):
                assertEquals(exp[i], str(row[0]) + "," + str(row[1]))

            # Query timeseries with align by device
            cursor.execute("SELECT \"status.2.3\", 'status.2.3' FROM root.ln.wf01.wt01 ALIGN BY DEVICE")
            result = cursor.fetchall()
            
            exp = ["1509465600000,root.ln wf01 wt01,true,'status.2.3',", "1509465600001,root.ln wf01 wt01,true,'status.2.3',", 
                  "1509465600002,root.ln wf01 wt01,false,'status.2.3',", "1509465600003,root.ln wf01 wt01,false,'status.2.3'"]
            for i, row in enumerate(result):
                assertEquals(exp[i], str(row[0]) + "," + "'status.2.3'," + str(row[1]))

            # Delete timeseries
            cursor.execute("DELETE FROM root.ln.wf01.wt01.\"status.2.3\" WHERE time < %s", ("1509465600001",))
            cursor.execute("DELETE TIMESERIES root.ln wf01 wt01.\"status.2.3\"")

        except Exception as e:
            print(str(e))

    def testIllegalStorageGroup(self):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            
            # Try to set illegal storage group
            cursor.execute("SET STORAGE GROUP TO root.\"ln\"")
        except mysql.connector.Error as e:
            assertEquals("315: The storage group name can only be characters, numbers and underscores. root.\"ln\" is not a legal path", str(e))

if __name__ == "__main__":
    IoTDBQuotedPathIT().test()
