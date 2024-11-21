import os
from pyspark.sql import SparkSession
from pyspark.conf import SparkConf
from pyspark.sql.functions import col
from typing import List, Any

class AbstractSparkTest:
    def __init__(self):
        self.temp_file = None
        self.nessie_port = 19121
        self.url = f"http://localhost:{nessie_port}/api/v1"
        self.spark_conf = SparkConf()
        self.spark_session = None

    @classmethod
    def create(cls, temp_dir: str) -> 'AbstractSparkTest':
        cls.temp_file = File(temp_dir)
        nessie_params = {
            "ref": "main",
            "uri": url,
            "warehouse": f"{temp_file.to_uri().toString()}"
        }
        
        for k, v in nessie_params.items():
            cls.spark_conf.set(f"spark.sql.catalog.nessie.{k}", v)
            cls.spark_conf.set(f"spark.sql.catalog.spark_catalog.{k}", v)

        cls.spark_conf.set("partition_overwrite_mode", "dynamic")
        cls.spark_conf.set("testing", True)
        cls.spark_conf.set("shuffle.partitions", 4)
        cls.spark_conf.set("sql.catalog.hive", "org.apache.iceberg.spark.SparkCatalog")
        cls.spark_conf.set("sql.catalog.hive.catalog-impl", "org.apache.iceberg.hive.HiveCatalog")
        cls.spark_conf.set("sql.catalog.nessie.catalog-impl", "org.apache.iceberg.nessie.NessieCatalog")

        cls.spark_session = SparkSession.builder.master("local[2]").config(cls.spark_conf).getOrCreate()
        cls.spark_session._jsc.sc().setLogLevel("WARN")

    @classmethod
    def tearDown(cls):
        if cls.spark_session is not None:
            cls.spark_session.stop()
            cls.spark_session = None

    @staticmethod
    def transform(table: List[Any]) -> List[List]:
        return [list(row) for row in table]

    @staticmethod
    def assertEqual(context, expected_row, actual_rows):
        if len(actual_rows) == 1:
            print(f"Expected {expected_row} but got {actual_rows[0]}")
        else:
            print(f"Expected {expected_row} but got {actual_rows}")

    @classmethod
    def sql(cls, query: str, *args: Any) -> List[List]:
        rows = cls.spark_session.sql(query.format(*args)).collect()
        
        if len(rows) < 1:
            return []

        return [list(row) for row in rows]

    @staticmethod
    def to_java(row):
        return list(map(lambda x: None if isinstance(x, str) else x, row))

    @classmethod
    def row(cls, *values: Any) -> List[Any]:
        return list(values)
