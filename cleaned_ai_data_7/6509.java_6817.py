import threading
import time
from unittest import TestCase

class TransactionLockingTaskMonitorTest(TestCase):

    # LockingTaskMonitor only functional in Headed mode

    THREAD_COUNT = 5

    def setUp(self):
        self.program = ProgramBuilder("test", "X86").getProgram()

    def tearDown(self):
        self.program.release()

    def test_transaction_wait_for_snapshot_lock(self):
        lock_monitor = self.program.lockForSnapshot(True, "Lock Test")
        try:
            for i in range(THREAD_COUNT):
                thread = threading.Thread(target=lambda: (
                    coordination_start.count_down(),
                    tx_id = None
                    try:
                        tx_id = self.program.startTransaction("Test")
                    except Exception as e:
                        print(str(e))
                        self.throwable = e
                    finally:
                        coordination_in_transaction.count_down()
                        if tx_id is not None:
                            self.program.endTransaction(tx_id, True)
                ), name="Test-" + str(i))
                thread.start()

            coordination_start.await(2)

            # Provide some time for threads to invoke startTransaction 
            # which should block each thread.  This is needed to 
            # provide some confidence in the coordination_in_transaction assertion below.
            time.sleep(0.5)

            # No transaction should have been issued yet
            self.assertEqual(THREAD_COUNT, coordination_in_transaction.get_count())

        finally:
            lock_monitor.releaseLock()

        # wait for all threads to obtain transaction
        coordination_in_transaction.await(2)

        # wait for all thread to terminate
        coordination_end.await(2)

        self.assertIsNone("Error occurred in transaction thread", self.throwable)

    def test_transaction_wait_for_lock(self):
        assert program.lock("test")
        try:
            for i in range(THREAD_COUNT):
                thread = threading.Thread(target=lambda: (
                    coordination_start.count_down(),
                    tx_id = None
                    try:
                        tx_id = self.program.startTransaction("Test")
                    except Exception as e:
                        print(str(e))
                        self.throwable = e
                    finally:
                        coordination_in_transaction.count_down()
                        if tx_id is not None:
                            self.program.endTransaction(tx_id, True)
                ), name="Test-" + str(i))
                thread.start()

            coordination_start.await(2)

            time.sleep(0.5)

            # No transaction should have been issued yet
            self.assertEqual(THREAD_COUNT, coordination_in_transaction.get_count())

        finally:
            program.unlock()

        # wait for all threads to obtain transaction
        coordination_in_transaction.await(2)

        # wait for all thread to terminate
        coordination_end.await(2)

        self.assertIsNone("Error occurred in transaction thread", self.throwable)
