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
