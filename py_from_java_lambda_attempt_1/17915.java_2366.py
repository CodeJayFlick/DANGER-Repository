Here is the translation of the Java code into Python:

```Python
import re

class LogicalPlanSmallTest:
    def test_limit(self):
        sql_str = "select * from root.vehicle.d1 limit 10"
        operator = self.generate_logical_plan(sql_str)
        assert isinstance(operator, QueryOperator), f"Expected {QueryOperator.__name__}, got {type(operator)}"
        special_clause_component = operator.get_special_clause_component()
        assert special_clause_component.get_row_limit() == 10
        assert special_clause_component.get_row_offset() == 0
        assert special_clause_component.get_series_limit() == 0
        assert special_clause_component.get_series_offset() == 0

    def test_offset(self):
        sql_str = "select * from root.vehicle.d1 limit 10 offset 20"
        operator = self.generate_logical_plan(sql_str)
        assert isinstance(operator, QueryOperator), f"Expected {QueryOperator.__name__}, got {type(operator)}"
        special_clause_component = operator.get_special_clause_component()
        assert special_clause_component.get_row_limit() == 10
        assert special_clause_component.get_row_offset() == 20
        assert special_clause_component.get_series_limit() == 0
        assert special_clause_component.get_series_offset() == 0

    def test_slimit(self):
        sql_str = "select * from root.vehicle.d1 limit 10 slimit 1"
        operator = self.generate_logical_plan(sql_str)
        assert isinstance(operator, QueryOperator), f"Expected {QueryOperator.__name__}, got {type(operator)}"
        special_clause_component = operator.get_special_clause_component()
        assert special_clause_component.get_row_limit() == 10
        assert special_clause_component.get_row_offset() == 0
        assert special_clause_component.get_series_limit() == 1
        assert special_clause_component.get_series_offset() == 0

    def test_soffset(self):
        sql_str = "select * from root.vehicle.d1 where s1 < 20 and time <= now() limit 50 slimit 10 soffset 100"
        operator = self.generate_logical_plan(sql_str)
        assert isinstance(operator, QueryOperator), f"Expected {QueryOperator.__name__}, got {type(operator)}"
        special_clause_component = operator.get_special_clause_component()
        assert special_clause_component.get_row_limit() == 50
        assert special_clause_component.get_row_offset() == 0
        assert special_clause_component.get_series_limit() == 10
        assert special_clause_component.get_series_offset() == 100

    def test_soffset_timestamp(self):
        sql_str = "select * from root.vehicle.d1 where s1 < 20 and timestamp <= now() limit 50 slimit 10 soffset 100"
        operator = self.generate_logical_plan(sql_str)
        assert isinstance(operator, QueryOperator), f"Expected {QueryOperator.__name__}, got {type(operator)}"
        special_clause_component = operator.get_special_clause_component()
        assert special_clause_component.get_row_limit() == 50
        assert special_clause_component.get_row_offset() == 0
        assert special_clause_component.get_series_limit() == 10
        assert special_clause_component.get_series_offset() == 100

    def test_limit_out_of_range(self):
        sql_str = "select * from root.vehicle.d1 where s1 < 20 and time <= now() limit 1111111111111111111111"
        try:
            self.generate_logical_plan(sql_str)
        except SQLParserException as e:
            assert str(e) == "Out of range. LIMIT <N>: N should be Int32."

    def test_limit_not_positive(self):
        sql_str = "select * from root.vehicle.d1 where s1 < 20 and time <= now() limit 0"
        try:
            self.generate_logical_plan(sql_str)
        except SQLParserException as e:
            assert str(e) == "LIMIT <N>: N should be greater than 0."

    def test_offset_out_of_range(self):
        sql_str = "select * from root.vehicle.d1 where s1 < 20 and time <= now() limit 1 offset 1111111111111111111111"
        try:
            self.generate_logical_plan(sql_str)
        except SQLParserException as e:
            assert str(e) == "Out of range. OFFSET <OFFSETValue>: OFFSETValue should be Int32."

    def test_offset_not_positive(self):
        sql_str = "select * from root.vehicle.d1 where s1 < 20 and time <= now() limit 1 offset -1"
        try:
            self.generate_logical_plan(sql_str)
        except SQLParserException as e:
            assert str(e) == "OFFSET <OFFSETValue>: OFFSETValue should >= 0."

    def test_slimit_out_of_range(self):
        sql_str = "select * from root.vehicle.d1 where s1 < 20 and time <= now() slimit 1111111111111111111111"
        try:
            self.generate_logical_plan(sql_str)
        except SQLParserException as e:
            assert str(e) == "Out of range. SLIMIT <SN>: SN should be Int32."

    def test_slimit_not_positive(self):
        sql_str = "select * from root.vehicle.d1 where s1 < 20 and time <= now() slimit 0"
        try:
            self.generate_logical_plan(sql_str)
        except SQLParserException as e:
            assert str(e) == "SLIMIT <SN>: SN should be greater than 0."

    def test_soffset_out_of_range(self):
        sql_str = "select * from root.vehicle.d1 where s1 < 20 and time <= now() slimit 1 soffset 1111111111111111111111"
        try:
            self.generate_logical_plan(sql_str)
        except SQLParserException as e:
            assert str(e) == "Out of range. SOFFSET <SOFFSETValue>: SOFFSETValue should be Int32."

    def test_disable_align(self):
        sql_str = "select * from root.vehicle.*** disable align"
        operator = self.generate_logical_plan(sql_str)
        assert isinstance(operator, QueryOperator), f"Expected {QueryOperator.__name__}, got {type(operator)}"
        assert not operator.is_align_by_time()

    def test_not_disable_align(self):
        sql_str = "select * from root.vehicle.***"
        operator = self.generate_logical_plan(sql_str)
        assert isinstance(operator, QueryOperator), f"Expected {QueryOperator.__name__}, got {type(operator)}"
        assert operator.is_align_by_time()

    def test_chinese_character(self):
        try:
            sql1 = "set storage group to root.一级"
            op = self.generate_logical_plan(sql1)
            assert isinstance(op, SetStorageGroupOperator), f"Expected {SetStorageGroupOperator.__name__}, got {type(op)}"
            partial_path = new PartialPath("root.一级")
            assert equal(partial_path, ((SetStorageGroupOperator) op).getPath())

        except IllegalPathException as e:
            print(str(e))

    def test_range_delete(self):
        try:
            sql1 = "delete from root.d1.s1 where time>=1 and time < 3"
            operator = self.generate_logical_plan(sql1)
            assert isinstance(operator, DeleteDataOperator), f"Expected {DeleteDataOperator.__name__}, got {type(operator)}"
            partial_paths = new ArrayList<PartialPath>()
            partial_paths.add(new PartialPath("root.d1.s1"))
            assert equal(partial_paths, ((DeleteDataOperator) operator).getPaths())
            start_time = 1
            end_time = 2
            assert equal(start_time, ((DeleteDataOperator) operator).getStartTime())
            assert equal(end_time, ((DeleteDataOperator) operator).getEndTime())

        except SQLParserException as e:
            print(str(e))

    def test_error_delete_range(self):
        try:
            sql_str = "delete from root.d1.s1 where time>=1 and time < 3 or time >1"
            self.generate_logical_plan(sql_str)
        except SQLParserException as e:
            assert str(e) == "For delete statement, where clause can only contain atomic expressions like : time > XXX, time <= XXX, or two atomic expressions connected by 'AND'"

    def test_regexp_query(self):
        sql_str = "SELECT a FROM root.sg.* WHERE a REGEXP 'string'"
        operator = self.generate_logical_plan(sql_str)
        assert isinstance(operator, QueryOperator), f"Expected {QueryOperator.__name__}, got {type(operator)}"
        query_operator = (QueryOperator) operator
        assert equal("a", query_operator.getSelectComponent().getResultColumns().get(0).getExpression().toString())
        assert equal("root.sg.*", query_operator.getFromComponent().getPrefixPaths().get(0).getFullPath())

    def generate_logical_plan(self, sql_str):
        return LogicalGenerator.generate(sql_str)

if __name__ == "__main__":
    test = LogicalPlanSmallTest()
    test.test_limit()
    test.test_offset()
    test.test_slimit()
    test.test_soffset()
    test.test_soffset_timestamp()
    test.test_limit_out_of_range()
    test.test_limit_not_positive()
    test.test_offset_out_of_range()
    test.test_offset_not_positive()
    test.test_slimit_out_of_range()
    test.test_slimit_not_positive()
    test.test_soffset_out_of_range()
    test.test_disable_align()
    test.test_not_disable_align()
    test.test_chinese_character()
    test.test_range_delete()
    test.test_error_delete_range()
    test.test_regexp_query()