import sqlite3


class TestUtils:
    @staticmethod
    def execute_sql(sql: str, connection) -> None:
        try:
            cursor = connection.cursor()
            cursor.execute(sql)
            connection.commit()
        except sqlite3.Error as e:
            print(f"An error occurred: {e}")

    @staticmethod
    def create_schema(connection) -> None:
        TestUtils.execute_sql("CREATE SCHEMA IF NOT EXISTS my_schema", connection)

    @staticmethod
    def delete_schema(connection) -> None:
        TestUtils.execute_sql("DROP SCHEMA IF EXISTS my_schema CASCADE", connection)

    @staticmethod
    def get_connection() -> sqlite3.Connection:
        conn = sqlite3.connect('test.db')
        return conn


# Example usage:

if __name__ == "__main__":
    try:
        conn = TestUtils.get_connection()
        TestUtils.create_schema(conn)
        # Your SQL commands here...
        conn.close()

    except Exception as e:
        print(f"An error occurred: {e}")
