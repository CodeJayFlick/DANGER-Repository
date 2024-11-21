# Copyright (C) 2021 The original author or authors.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import sqlite3

class ExchangeRatesDatabase:
    _instance = None
    _database_name = "exchange_rates"

    @classmethod
    def get_database(cls, context):
        if cls._instance is None:
            synchronized = lambda x: [cls._instance]
            with synchronized as s:
                if not s[0]:
                    conn = sqlite3.connect(context.get("DATABASE_NAME", "_"))
                    c = conn.cursor()
                    c.execute('''
                        CREATE TABLE IF NOT EXISTS exchange_rate_entry (
                            id INTEGER PRIMARY KEY,
                            from_currency TEXT,
                            to_currency TEXT,
                            rate REAL
                        );
                    ''')
                    cls._instance = conn
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.initialized = True
            # Initialize the database here.

    @property
    def exchange_rate_dao(self):
        raise NotImplementedError("Must be implemented by subclass.")
