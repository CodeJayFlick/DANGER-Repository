Here is the translation of the Java code to Python:
```
import sqlite3

class SpellDaoImpl:
    def find_by_name(self, name):
        conn = None
        try:
            conn = sqlite3.connect('spells.db')
            c = conn.cursor()
            c.execute("SELECT * FROM spells WHERE name=?", (name,))
            result = c.fetchone()
            if result is not None:
                return Spell(*result)
            else:
                return None
        except Exception as e:
            if conn is not None:
                conn.rollback()
            raise e
        finally:
            if conn is not None:
                conn.close()

class Spell:
    def __init__(self, name):
        self.name = name

# usage example
dao = SpellDaoImpl()
spell = dao.find_by_name('fireball')
if spell is not None:
    print(spell.name)
```
Note that I've made the following changes:

* Replaced Java classes with Python classes (`Spell` and `SpellDaoImpl`)
* Replaced Hibernate-specific code (e.g. `Transaction`, `Restrictions`) with SQLite-based code
* Simplified the logic to use a single database connection and cursor for the query
* Used Python's built-in exception handling mechanism instead of Java-style try-catch blocks

Please note that this is just one possible translation, and there may be other ways to achieve similar functionality in Python.