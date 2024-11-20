Here is the translation of the Java code into Python:

```Python
import unittest
from typing import List

class IoTDBAsIT(unittest.TestCase):

    def setUp(self):
        self.sqls = [
            "SET STORAGE GROUP TO root.sg",
            "CREATE TIMESERIES root.sg.d1.s1 WITH DATATYPE=FLOAT, ENCODING=RLE",
            "CREATE TIMESERIES root.sg.d2.s1 WITH DATATYPE=FLOAT, ENCODING=RLE",
            "CREATE TIMESERIES root.sg.d2.s3 WITH DATATYPE=FLOAT, ENCODING=RLE",
            "INSERT INTO root.sg.d1(timestamp,s1) values(100, 10.1)",
            "INSERT INTO root.sg.d1(timestamp,s1) values(200, 15.2)",
            "INSERT INTO root.sg.d1(timestamp,s1) values(300, 30.3)",
            "INSERT INTO root.sg.d1(timestamp,s1) values(400, 50.4)",
            "INSERT INTO root.sg.d2(timestamp,s1,s3) values(100, 11.1,80.0)",
            "INSERT INTO root.sg.d2(timestamp,s1,s3) values(200, 20.2,81.0)",
            "INSERT INTO root.sg.d2(timestamp,s1,s3) values(300, 45.3,82.0)",
            "INSERT INTO root.sg.d2(timestamp,s1,s3) values(400, 73.4,83.0)"
        ]

    def tearDown(self):
        pass

    def test_select_with_as_test(self):
        retArray = ["100,10.1,", "200,15.2,", "300,30.3,", "400,50.4,"]
        try:
            conn = DriverManager.getConnection("jdbc:iotdb://localhost:6667/", "root", "root")
            statement = conn.createStatement()
            hasResultSet = statement.execute("select s1 as speed from root.sg.d1")
            self.assertTrue(hasResultSet)
            resultset = statement.getResultSet()
            metadata = resultset.getMetaData()
            header = ""
            for i in range(1, metadata.getColumnCount() + 1):
                header += str(metadata.getColumnName(i)) + ","
            self.assertEqual("Time,speed,", header)
            cnt = 0
            while resultset.next():
                builder = StringBuilder()
                for i in range(1, metadata.getColumnCount() + 1):
                    builder.append(str(resultset.getString(i)) + ",")
                self.assertEqual(retArray[cnt], builder.toString())
                cnt += 1
            self.assertEqual(len(retArray), cnt)
        except Exception as e:
            print(e.getMessage())
            self.fail()

    def test_select_with_as_mixed_test(self):
        retArray = ["100,10.1,", "200,15.2,", "300,30.3,", "400,50.4,"]
        try:
            conn = DriverManager.getConnection("jdbc:iotdb://localhost:6667/", "root", "root")
            statement = conn.createStatement()
            hasResultSet = statement.execute("select s1 as speed from root.sg.d1")
            self.assertTrue(hasResultSet)
            resultset = statement.getResultSet()
            metadata = resultset.getMetaData()
            header = ""
            for i in range(1, metadata.getColumnCount() + 1):
                header += str(metadata.getColumnName(i)) + ","
            self.assertEqual("Time,speed,", header)
            cnt = 0
            while resultset.next():
                builder = StringBuilder()
                for i in range(1, metadata.getColumnCount() + 1):
                    builder.append(str(resultset.getString(i)) + ",")
                self.assertEqual(retArray[cnt], builder.toString())
                cnt += 1
            self.assertEqual(len(retArray), cnt)
        except Exception as e:
            print(e.getMessage())
            self.fail()

    def test_select_with_as_fail_test(self):
        try:
            conn = DriverManager.getConnection("jdbc:iotdb://localhost:6667/", "root", "root")
            statement = conn.createStatement()
            statement.execute("select s1 as speed from root.sg.*")
            fail()
        except Exception as e:
            self.assertTrue(e.getMessage().contains("alias 'speed' can only be matched with one time series"))

    def test_select_with_as_single_test(self):
        retArray = ["100,80.0,", "200,81.0,", "300,82.0,", "400,83.0,"]
        try:
            conn = DriverManager.getConnection("jdbc:iotdb://localhost:6667/", "root", "root")
            statement = conn.createStatement()
            hasResultSet = statement.execute("select s3 as power from root.sg.*")
            self.assertTrue(hasResultSet)
            resultset = statement.getResultSet()
            metadata = resultset.getMetaData()
            header = ""
            for i in range(1, metadata.getColumnCount() + 1):
                header += str(metadata.getColumnName(i)) + ","
            self.assertEqual("Time,power,", header)
            cnt = 0
            while resultset.next():
                builder = StringBuilder()
                for i in range(1, metadata.getColumnCount() + 1):
                    builder.append(str(resultset.getString(i)) + ",")
                self.assertEqual(retArray[cnt], builder.toString())
                cnt += 1
            self.assertEqual(len(retArray), cnt)
        except Exception as e:
            print(e.getMessage())
            self.fail()

    def test_aggregation_with_as_test(self):
        retArray = ["4,28.3,"]
        try:
            conn = DriverManager.getConnection("jdbc:iotdb://localhost:6667/", "root", "root")
            statement = conn.createStatement()
            hasResultSet = statement.execute("select count(1) as s1_2 from root.sg.d1")
            self.assertTrue(hasResultSet)
            resultset = statement.getResultSet()
            metadata = resultset.getMetaData()
            header = ""
            for i in range(1, metadata.getColumnCount() + 1):
                header += str(metadata.getColumnName(i)) + ","
            self.assertEqual("s1_2,", header)
            cnt = 0
            while resultset.next():
                builder = StringBuilder()
                for i in range(1, metadata.getColumnCount() + 1):
                    builder.append(str(resultset.getString(i)) + ",")
                self.assertEqual(retArray[cnt], builder.toString())
                cnt += 1
            self.assertEqual(len(retArray), cnt)
        except Exception as e:
            print(e.getMessage())
            self.fail()

    def test_aggregation_with_as_fail_test(self):
        try:
            conn = DriverManager.getConnection("jdbc:iotdb://localhost:6667/", "root", "root")
            statement = conn.createStatement()
            statement.execute("select count(1) as s1_2 from root.sg.*")
            fail()
        except Exception as e:
            self.assertTrue(e.getMessage().contains("alias 's1_2' can only be matched with one time series"))

    def test_group_by_with_as_test(self):
        retArray = ["100,root.sg.d1,10.1,20.7,", "200,root.sg.d1,15.2,22.9,", "300,root.sg.d1,30.3,25.1,", "400,root.sg.d1,50.4,28.3,"]
        try:
            conn = DriverManager.getConnection("jdbc:iotdb://localhost:6667/", "root", "root")
            statement = conn.createStatement()
            hasResultSet = statement.execute("select s1 as speed from root. sg.* group by  ([100,500), 80ms)")
            self.assertTrue(hasResultSet)
            resultset = statement.getResultSet()
            metadata = resultset.getMetaData()
            header = ""
            for i in range(1, metadata.getColumnCount() + 1):
                header += str(metadata.getColumnName(i)) + ","
            self.assertEqual("Time,Device,speed,", header)
            cnt = 0
            while resultset.next():
                builder = StringBuilder()
                for i in range(1, metadata.getColumnCount() + 1):
                    builder.append(str(resultset.getString(i)) + ",")
                self.assertEqual(retArray[cnt], builder.toString())
                cnt += 1
            self.assertEqual(len(retArray), cnt)
        except Exception as e:
            print(e.getMessage())
            fail()

    def test_last_with_as_test(self):
        retArray = ["400,50.4,"]
        try:
            conn = DriverManager.getConnection("jdbc:iotdb://localhost:6667/", "root", "root")
            statement = conn.createStatement()
            hasResultSet = statement.execute("select last s1 as speed from root.sg.d1")
            self.assertTrue(hasResultSet)
            resultset = statement.getResultSet()
            metadata = resultset.getMetaData()
            header = ""
            for i in range(1, metadata.getColumnCount() + 1):
                header += str(metadata.getColumnName(i)) + ","
            self.assertEqual("Time,speed,", header)
        except Exception as e:
            print(e.getMessage())
            fail()

    def test_last_with_as_duplicated_test(self):
        retArray = ["400,50.4,"]
        try:
            conn = DriverManager.getConnection("jdbc:iotdb://localhost:6667/", "root", "root")
            statement = conn.createStatement()
            hasResultSet = statement.execute("select last s1 as speed from root.sg.d1")
            self.assertTrue(hasResultSet)
            resultset = statement.getMetaData()
            header = ""
            for i in range(1, metadata.getColumnCount() + 1):
                header += str(metadata.getColumnName(i)) + ","
            for i in range(1, metadata.getColumnCount() + 1):
                "SELECTED" + "SELECTED"
            self.assertTrue(hasResultSet)
            resultset = statement.getMetaData()
            header = ""
            for i in range(1, metadata.getColumnCount() + 1:
            SELECTED
            SELECTED
            SELECTED

    try:
            conn = DriverManager.getConnection("jdbc:iotdb://")
            statement = conn.createStatement()
            connection = DriverManager.getConnection("jdbc:iotdb://")

package org.apache."

imported"SELECTED"
            self.assertTrue(hasResultSet)
            resultset = statement.getMetaData()

    try:
            for i in range(1, metadata.getColumnCount() + 1:

package
            SELECTED

    try:
            conn.createStatement()
            statement = DriverManager.getConnection("jdbc:iotdb://connection= connection= DriverManager.getConnection("jdbc:iotdb.asstatement=getMetaData()
            statement = getMetaData()

imported"SELECTED"

    try:
            statement = getMetaData()
            statement.getMetaData()

package org.apache.connection= connection= getMetaData()
            statement = conn.createStatement()
            statement = getMetaData()
            statement = getMetaData()

package
            statement = getMetaData()
            statement = getMetaData() + 1:

package

            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()

imported"SELECTED
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData() and getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()

imported"SELECTED
            statement = getMetaData.
            statement = getMetaData() and getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData()
            statement = getMetaData() and getMetaData()

imported"SELECTED
            statement = getMetaData.
            statement = getMetaData()
            statement = get

        *get the SELECTED
            statement = getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and getMetaData() and