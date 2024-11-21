import csv
from io import StringIO
import unittest


class ExportCsvTest(unittest.TestCase):

    def setUp(self):
        self.command = None
        if 'windows' in str.lower(sys.platform):
            self.command = ["cmd.exe", "/c", "path_to_your_file/export-csv.bat"]
        else:
            self.command = ["sh", "path_to_your_file/tools/export-csv.sh"]

    def tearDown(self):
        EnvironmentUtils.clean_env()

    @unittest.skipIf(not os.path.exists("target/dump0.csv"), "CSV file not found")
    def testExport(self):
        params = {"-td": "target/", "-q": "select c1, c2, c3 from root.test.t1"}
        self.prepare_data()
        self.test_method(params)
        with open('target/dump0.csv', 'r') as f:
            reader = csv.reader(f)
            real_records = [row[0].split(',') for row in reader]
        records = []
        with StringIO() as sio:
            writer = csv.writer(sio, delimiter=',')
            self.records_to_csv(records, writer)
            actual_records = [record.strip().replace('"', '') for record in sio.getvalue().strip().split('\n')]
        self.assertEqual(real_records[0], actual_records[0])
        self.assertEqual(real_records[1], actual_records[1])

    @unittest.skipIf(not os.path.exists("target/dump0.csv"), "CSV file not found")
    def testWithDataType(self):
        params = {"-td": "target/", "-datatype": True, "-q": "select c1, c2, c3 from root.test.t1"}
        self.prepare_data()
        self.test_method(params)
        with open('target/dump0.csv', 'r') as f:
            reader = csv.reader(f)
            real_records = [row[0].split(',') for row in reader]
        records = []
        with StringIO() as sio:
            writer = csv.writer(sio, delimiter=',')
            self.records_to_csv(records, writer)
            actual_records = [record.strip().replace('"', '') for record in sio.getvalue().strip().split('\n')]
        self.assertEqual(real_records[0], actual_records[0])
        self.assertEqual(real_records[1], actual_records[1])

    @unittest.skipIf(not os.path.exists("target/dump0.csv"), "CSV file not found")
    def testAggregationQuery(self):
        params = {"-td": "target/", "-q": "select count(c1), count(c2), count(c3) from root.test.t1"}
        self.prepare_data()
        self.test_method(params)
        with open('target/dump0.csv', 'r') as f:
            reader = csv.reader(f)
            real_records = [row[0].split(',') for row in reader]
        records = []
        with StringIO() as sio:
            writer = csv.writer(sio, delimiter=',')
            self.records_to_csv(records, writer)
            actual_records = [record.strip().replace('"', '') for record in sio.getvalue().strip().split('\n')]
        self.assertEqual(real_records[0], actual_records[0])
        self.assertEqual(real_records[1], actual_records[1])

    def prepare_data(self):
        session = Session("127.0.0.1", 6667, "root", "root")
        session.open()

        device_id = "root.test.t1"
        measurements = ["c1", "c2", "c3"]

        values = [1.0, "\"abc\",aa", "abbe'"]
        session.insert_record(device_id, 1L, measurements, values)

    def test_method(self, params):
        # Your code here
        pass

    def records_to_csv(self, records, writer):
        for record in records:
            writer.writerow([record])
