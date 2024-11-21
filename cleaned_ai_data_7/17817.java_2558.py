import unittest
from io import StringIO
import mysql.connector

class IoTDBCreateStorageGroupIT(unittest.TestCase):

    def setUp(self):
        self.cnx = mysql.connector.connect(
            user='root', password='root',
            host='127.0.0.1',
            port=6667,
            database='iotdb'
        )
        self.cursor = self.cnx.cursor()

    def tearDown(self):
        self.cursor.close()
        self.cnx.close()

    @unittest.skip("Not implemented yet")
    def testCreateStorageGroup(self):

        storage_groups = ["root.sg1", "root.sg2", "root.sg3"]

        for sg in storage_groups:
            try:
                self.cursor.execute(f"CREATE STORAGE GROUP {sg}")
            except mysql.connector.Error as err:
                print(err)

        # ensure that current StorageGroup in cache is right.
        create_storage_group_tool(self, storage_groups)

    @unittest.skip("Not implemented yet")
    def testCreateExistStorageGroup1(self):

        sg = "root.sg"

        try:
            self.cursor.execute(f"SET STORAGE GROUP TO {sg}")
        except mysql.connector.Error as err:
            print(err)
            self.assertEqual(str(err), "300: root.sg has already been set to storage group")

    @unittest.skip("Not implemented yet")
    def testCreateExistStorageGroup2(self):

        try:
            self.cursor.execute(f"CREATE STORAGE GROUP {sg}.device")
        except mysql.connector.Error as err:
            print(err)
            self.assertEqual(str(err), "300: root.sg has already been set to storage group")

    @unittest.skip("Not implemented yet")
    def create_storage_group_tool(self, storage_groups):
        try:
            self.cursor.execute("SHOW STORAGE GROUP")
        except mysql.connector.Error as err:
            print(err)

        result = []
        for row in self.cursor.fetchall():
            if row[0] != '':
                result.append(row[0])

        self.assertEqual(len(result), 3)
        result.sort()
        self.assertEqual(storage_groups[0], result[0])
        self.assertEqual(storage_groups[1], result[1])
        self.assertEqual(storage_groups[2], result[2])


if __name__ == '__main__':
    unittest.main()
