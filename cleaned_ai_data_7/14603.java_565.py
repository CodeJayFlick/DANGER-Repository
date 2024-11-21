import sqlite3

class SimpleObjectsTearDown:
    def __init__(self):
        self.conn = sqlite3.connect(':memory:')
        self.cursor = self.conn.cursor()

    def execute(self, execution_context=None):
        query = "DELETE FROM simple.SimpleObject"
        try:
            self.cursor.execute(query)
            self.conn.commit()
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if self.conn:
                self.conn.close()


# Usage
tear_down = SimpleObjectsTearDown()
tear_down.execute()
