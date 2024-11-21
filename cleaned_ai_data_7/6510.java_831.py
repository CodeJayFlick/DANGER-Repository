import threading
import time
from unittest import TestCase

class TransactionLockingTest(TestCase):

    def setUp(self):
        self.program = ProgramBuilder("test", "X86").getProgram()

    def tearDown(self):
        self.program.release()

    def test_transaction_wait_for_lock(self):
        program_lockedLatch = threading.Lock()
        lock_exceptionLatch = threading.Condition(threading.Lock())

        exception_ref = [None]

        # setup transaction thread
        tx_thread = threading.Thread(target=lambda: 
            try:
                with program_lockedLatch:
                    tx_id = self.program.startTransaction("Test")
                    time.sleep(2)
                    self.program.endTransaction(tx_id, True)
            except Exception as e:
                exception_ref[0] = e)

        tx_thread.start()

        #setup lock thread
        lock_thread = threading.Thread(target=lambda: 
            try:
                with program_lockedLatch:
                    got_lock = self.program.lock("TestLock")
                    if not got_lock:
                        raise AssertionError("Failed to obtain lock")

                time.sleep(2)
                lock_exceptionLatch.acquire()
                lock_exceptionLatch.notify_all()

                finally:
                    self.program.unlock()
            except Exception as e:
                exception_ref[0] = e)

        lock_thread.start()

        # wait for transaction test thread to complete
        tx_thread.join(timeout=2000)
        assert not tx_thread.is_alive(), "Tx-Thread may be hung"

        exc = exception_ref[0]
        if exc is not None:
            self.failWithException("Transaction Failure", exc)

    def fail_with_exception(self, message, e):
        raise AssertionError(f"{message}: {e}")

class ProgramBuilder:

    def __init__(self, name, architecture, test_case):
        pass

    def get_program(self):
        return "Program"

class DomainObjectLockedException:
    pass
