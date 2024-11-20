class PostgresDatabaseAdapter:
    def __init__(self, config, db):
        pass

    def database_sql_format_parameters(self) -> dict:
        return {
            'BLOB': "BYTEA",
            'HASH': "VARCHAR",
            'KEY_PREFIX': "VARCHAR",
            'KEY': "VARCHAR",
            'NAMED_REF': "VARCHAR",
            'NAMED_REF_TYPE': "VARCHAR",
            'CONTENTS_ID': "VARCHAR",
            'INTEGER': "BIGINT"
        }

    def metadata_upper_case(self) -> bool:
        return False

    def batch_ddl(self) -> bool:
        # Postgres + Cockroach can perform DDL-batches, but that doesn't always work :(
        return False
