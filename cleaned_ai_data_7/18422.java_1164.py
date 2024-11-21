import unittest
from datetime import datetime as dt

class TimePlainEncodeReadTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        TSFileDescriptor.getInstance().getConfig().setTimeEncoder("PLAIN")
        FileGenerator.generateFile()
        cls.roTsFile = TsFileSequenceReader(FileGenerator.outputDataFile)

    @classmethod
    def tearDownClass(cls):
        if cls.roTsFile is not None:
            cls.roTsFile.close()
        FileGenerator.after()

    def test_query_one_measurement_without_filter(self):
        path_list = []
        path_list.append(Path("d1", "s1"))
        query_expression = QueryExpression.create(path_list, None)
        data_set = self.roTsFile.query(query_expression)

        count = 0
        while data_set.has_next():
            row_record = data_set.next()
            if count == 0:
                self.assertEqual(dt(2017, 12, 31, 14, 56, 21).timestamp(), row_record.get_timestamp())
            elif count == 499:
                self.assertEqual(dt(2017, 12, 31, 14, 56, 23).timestamp(), row_record.get_timestamp())
            count += 1
        self.assertEqual(count, 500)

    def test_query_two_measurements_without_filter(self):
        path_list = []
        path_list.append(Path("d1", "s1"))
        path_list.append(Path("d2", "s2"))
        query_expression = QueryExpression.create(path_list, None)
        data_set = self.roTsFile.query(query_expression)

        count = 0
        while data_set.has_next():
            row_record = data_set.next()
            if count == 0:
                pass
            count += 1
        self.assertEqual(count, 750)

    def test_query_two_measurements_with_single_filter(self):
        path_list = []
        path_list.append(Path("d2", "s1"))
        path_list.append(Path("d2", "s4"))
        val_filter = SingleSeriesExpression(Path("d2", "s2"), ValueFilter.gt(9722))
        t_filter = BinaryExpression.and(
            GlobalTimeExpression(TimeFilter.ge(dt(2017, 12, 31, 14, 56, 21).timestamp())),
            GlobalTimeExpression(TimeFilter.lt(dt(2017, 12, 31, 14, 56, 22).timestamp()))
        )
        final_filter = BinaryExpression.and(val_filter, t_filter)
        query_expression = QueryExpression.create(path_list, final_filter)
        data_set = self.roTsFile.query(query_expression)

    def test_query_with_two_series_time_value_filter_cross(self):
        path_list = []
        path_list.append(Path("d2", "s2"))
        val_filter = SingleSeriesExpression(Path("d2", "s2"), ValueFilter.neq(9722))
        t_filter = BinaryExpression.and(
            GlobalTimeExpression(TimeFilter.ge(dt(2017, 12, 31, 14, 56, 21).timestamp())),
            GlobalTimeExpression(TimeFilter.lt(dt(2017, 12, 31, 14, 56, 22).timestamp()))
        )
        final_filter = BinaryExpression.and(val_filter, t_filter)
        query_expression = QueryExpression.create(path_list, final_filter)
        data_set = self.roTsFile.query(query_expression)

    def test_query_boolean_test(self):
        path_list = []
        path_list.append(Path("d1", "s5"))
        val_filter = SingleSeriesExpression(Path("d1", "s5"), ValueFilter.eq(False))
        t_filter = BinaryExpression.and(
            GlobalTimeExpression(TimeFilter.ge(dt(2017, 12, 31, 14, 56, 21).timestamp())),
            GlobalTimeExpression(TimeFilter.lt(dt(2017, 12, 31, 14, 56, 22).timestamp()))
        )
        final_filter = BinaryExpression.and(val_filter, t_filter)
        query_expression = QueryExpression.create(path_list, final_filter)
        data_set = self.roTsFile.query(query_expression)

    def test_query_string_test(self):
        path_list = []
        path_list.append(Path("d1", "s4"))
        val_filter = SingleSeriesExpression(Path("d1", "s4"), ValueFilter.gt(Binary("dog97")))
        t_filter = BinaryExpression.and(
            GlobalTimeExpression(TimeFilter.ge(dt(2017, 12, 31, 14, 56, 21).timestamp())),
            GlobalTimeExpression(TimeFilter.lt(dt(2017, 12, 31, 14, 56, 22).timestamp()))
        )
        final_filter = BinaryExpression.and(val_filter, t_filter)
        query_expression = QueryExpression.create(path_list, final_filter)
        data_set = self.roTsFile.query(query_expression)

    def test_query_float_test(self):
        path_list = []
        path_list.append(Path("d1", "s6"))
        val_filter = SingleSeriesExpression(Path("d1", "s6"), ValueFilter.gt(103.0))
        t_filter = BinaryExpression.and(
            GlobalTimeExpression(TimeFilter.ge(dt(2017, 12, 31, 14, 56, 21).timestamp())),
            GlobalTimeExpression(TimeFilter.lt(dt(2017, 12, 31, 14, 56, 22).timestamp()))
        )
        final_filter = BinaryExpression.and(val_filter, t_filter)
        query_expression = QueryExpression.create(path_list, final_filter)
        data_set = self.roTsFile.query(query_expression)

    def test_query_double_test(self):
        path_list = []
        path_list.append(Path("d1", "s7"))
        val_filter = SingleSeriesExpression(Path("d1", "s7"), ValueFilter.gt(7.0))
        t_filter = BinaryExpression.and(
            GlobalTimeExpression(TimeFilter.ge(dt(2017, 12, 31, 14, 56, 21).timestamp())),
            GlobalTimeExpression(TimeFilter.lt(dt(2017, 12, 31, 14, 56, 22).timestamp()))
        )
        final_filter = BinaryExpression.and(val_filter, t_filter)
        query_expression = QueryExpression.create(path_list, final_filter)
        data_set = self.roTsFile.query(query_expression)

if __name__ == '__main__':
    unittest.main()
