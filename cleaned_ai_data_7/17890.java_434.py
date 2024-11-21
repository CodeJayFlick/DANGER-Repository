import sqlite3
from unittest import TestCase

class IoTDBTriggerManagementIT(TestCase):

    def setUp(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE root.vehicle.d1.s1 (ts INTEGER, v FLOAT)
        ''')
        c.execute('''
            CREATE TABLE root.vehicle.d1.s2 (ts INTEGER, v DOUBLE)
        ''')
        c.execute('''
            CREATE TABLE root.vehicle.d1.s3 (ts INTEGER, v INT32)
        ''')
        c.execute('''
            CREATE TABLE root.vehicle.d1.s4 (ts INTEGER, v INT64)
        ''')

    def tearDown(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()
        c.execute("DROP TABLE IF EXISTS root.vehicle.d1.s1")
        c.execute("DROP TABLE IF EXISTS root.vehicle.d1.s2")
        c.execute("DROP TABLE IF EXISTS root.vehicle.d1.s3")
        c.execute("DROP TABLE IF EXISTS root.vehicle.d1.s4")

    def testManageTriggersNormally(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                CREATE TRIGGER trigger-1
                BEFORE INSERT ON root.vehicle.d1.s1
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Accumulator';
                END;
            ''')
            c.execute('''
                CREATE TRIGGER trigger-2
                AFTER INSERT ON root.vehicle.d1.s2
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Counter';
                END;
            ''')

            rs = c.execute("SELECT name FROM sqlite_master WHERE type='table'")
            self.assertFalse(rs.fetchone())

            c.execute('''
                CREATE TRIGGER trigger-3
                BEFORE INSERT ON root.vehicle.d1.s4
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Accumulator';
                END;
            ''')

        except sqlite3.Error as e:
            self.fail(e.args[0])

    def testRegisterOnNonMeasurementMNode(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                CREATE TRIGGER trigger-2
                BEFORE INSERT ON root.vehicle.d1
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Accumulator';
                END;
            ''')
            self.fail("Expected SQLException")

        except sqlite3.Error as e:
            self.assertTrue(e.args[0].startswith('MNode [root.vehicle.d1] is not a MeasurementMNode.'))

    def testRegisterOnNonExistentMNode(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                CREATE TRIGGER trigger-2
                BEFORE INSERT ON root.nonexistent.d1
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Accumulator';
                END;
            ''')
            self.fail("Expected SQLException")

        except sqlite3.Error as e:
            self.assertTrue(e.args[0].startswith('Path [root.nonexistent.d1] does not exist'))

    def testRegisterInvalidClass(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                CREATE TRIGGER trigger-2
                BEFORE INSERT ON root.vehicle.d1.s1
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Nonexistent';
                END;
            ''')
            self.fail("Expected SQLException")

        except sqlite3.Error as e:
            self.assertTrue(e.args[0].startswith('Failed to reflect Trigger trigger-2'))

    def testRegisterSameTriggers(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                CREATE TRIGGER trigger-1
                BEFORE INSERT ON root.vehicle.d1.s1
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Accumulator';
                END;
            ''')
            c.execute('''
                CREATE TRIGGER trigger-2
                AFTER INSERT ON root.vehicle.d1.s2
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Counter';
                END;
            ''')

        except sqlite3.Error as e:
            self.fail(e.args[0])

    def testRegisterTriggersWithSameNameButDifferentClasses(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                CREATE TRIGGER trigger-1
                BEFORE INSERT ON root.vehicle.d1.s1
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Accumulator';
                END;
            ''')
            c.execute('''
                CREATE TRIGGER trigger-2
                AFTER INSERT ON root.vehicle.d1.s2
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Counter';
                END;
            ''')

        except sqlite3.Error as e:
            self.fail(e.args[0])

    def testCreateAndDropSeveralTimes(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                CREATE TRIGGER trigger-1
                BEFORE INSERT ON root.vehicle.d1.s1
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Accumulator';
                END;
            ''')
            ((Accumulator) TriggerRegistrationService.getInstance().getTriggerInstance("trigger-1")).setAccumulator(1234)

        except sqlite3.Error as e:
            self.fail(e.args[0])

    def testDropNonExistentTrigger(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                DROP TRIGGER trigger-1
            ''')
            self.fail("Expected SQLException")

        except sqlite3.Error as e:
            self.assertTrue(e.args[0].startswith('Trigger trigger-1 does not exist'))

    def testStartNonExistentTrigger(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                START TRIGGER trigger-1
            ''')
            self.fail("Expected SQLException")

        except sqlite3.Error as e:
            self.assertTrue(e.args[0].startswith('Trigger trigger-1 does not exist'))

    def testStartStartedTrigger(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                CREATE TRIGGER trigger-1
                BEFORE INSERT ON root.vehicle.d1.s1
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Accumulator';
                END;
            ''')
            c.execute('''
                START TRIGGER trigger-1
            ''')

        except sqlite3.Error as e:
            self.fail(e.args[0])

    def testStopNonExistentTrigger(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                STOP TRIGGER trigger-1
            ''')
            self.fail("Expected SQLException")

        except sqlite3.Error as e:
            self.assertTrue(e.args[0].startswith('Trigger trigger-1 does not exist'))

    def testStopStoppedTrigger(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                CREATE TRIGGER trigger-1
                BEFORE INSERT ON root.vehicle.d1.s1
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Accumulator';
                END;
            ''')
            c.execute('''
                STOP TRIGGER trigger-1
            ''')

        except sqlite3.Error as e:
            self.fail(e.args[0])

    def testStopAndStartTriggerMultipleTimesNormally(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                CREATE TRIGGER trigger-1
                BEFORE INSERT ON root.vehicle.d1.s4
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Accumulator';
                END;
            ''')
            ((Accumulator) TriggerRegistrationService.getInstance().getTriggerInstance("trigger-1")).setAccumulator(1234)

        except sqlite3.Error as e:
            self.fail(e.args[0])

    def testRecovery(self):
        conn = sqlite3.connect(':memory:')
        c = conn.cursor()

        try:
            c.execute('''
                CREATE TRIGGER trigger-1
                BEFORE INSERT ON root.vehicle.d1.s4
                FOR EACH ROW BEGIN
                    SELECT 'org.apache.iotdb.db.engine.trigger.example.Accumulator';
                END;
            ''')
            ((Accumulator) TriggerRegistrationService.getInstance().getTriggerInstance("trigger-1")).setAccumulator(1234)

        except sqlite3.Error as e:
            self.fail(e.args[0])

if __name__ == '__main__':
    unittest.main()
