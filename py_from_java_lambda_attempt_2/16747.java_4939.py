Here is the translation of the Java code into Python:

```Python
import iotdb_python as IoTDBClient
from iotdb_python import exceptions as IoTDBSQLException
import time

class JDBCEmployee:
    def __init__(self):
        pass

    @staticmethod
    def main():
        try:
            connection = IoTDBClient.create_connection("127.0.0.1:6667", "root", "root")
            statement = connection.createStatement()

            # set JDBC fetchSize
            statement.setFetchSize(10000)

            try:
                statement.execute("SET STORAGE GROUP TO root.sgl")
                statement.execute(
                    """CREATE TIMESERIES root.sgl.d1.s1 WITH DATATYPE=INT64, ENCODING=RLE, COMPRESSOR=SNAPPY"""
                )
                statement.execute(
                    """CREATE TIMESERIES root.sgl.d1.s2 WITH DATATYPE=INT64, ENCODING=RLE, COMPRESSOR=SNAPPY"""
                )
                statement.execute(
                    """CREATE TIMESERIES root.sgl.d1.s3 WITH DATATYPE=INT64, ENCODING=RLE, COMPRESSOR=SNAPPY"""
                )

            except IoTDBSQLException as e:
                print(e.getMessage())

            for i in range(101):
                statement.addBatch(JDBCEmployee.prepare_insert_statment(i))
            statement.executeBatch()
            statement.clearBatch()

            result_set = statement.executeQuery("SELECT * FROM root WHERE time <= 10")
            JDBCEmployee.output_result(result_set)
            result_set = statement.executeQuery("SELECT COUNT(*) FROM root")
            JDBCEmployee.output_result(result_set)
            result_set = statement.executeQuery(
                """SELECT COUNT(*) FROM root WHERE time >= 1 AND time <= 100 GROUP BY ([0, 100), 20ms, 20ms)"""
            )
            JDBCEmployee.output_result(result_set)

        except IoTDBSQLException as e:
            print(e.getMessage())

    @staticmethod
    def prepare_insert_statment(time):
        return f"INSERT INTO root.sgl.d1(timestamp, s1, s2, s3) VALUES ({time}, 1, 1, 1)"

    @staticmethod
    def output_result(result_set):
        if result_set is not None:
            print("--------------------------")
            meta_data = result_set.getMetaData()
            column_count = meta_data.getColumnCount()
            for i in range(column_count):
                print(meta_data.getColumnLabel(i + 1), end=" ")
            print()

            while True:
                try:
                    for i in range(1, column_count + 1):
                        if i == column_count:
                            break
                        print(result_set.getString(i), end=", ")
                    print()
                    result_set.next()
                except Exception as e:
                    break

            print("--------------------------\n")


if __name__ == "__main__":
    JDBCEmployee.main()

```

Note: This code is not tested and may require additional setup to work correctly.