Here is the equivalent Python code for the given Java code:

```Python
import threading
from queue import Queue
import time
import random

class TestDataKeyModel:
    ROWCOUNT = 1000
    BYTE_COL = 'byte'
    SHORT_ COL = 'short'
    INT_COL = 'int'
    LONG_COL = 'long'
    FLOAT_COL = 'float'
    DOUBLE_COL = 'double'

class SpyEventRecorder:
    def __init__(self, name):
        self.name = name

    def record(self, message):
        print(f"[{self.name}] {message}")

class TestLoadingPolicy:
    pass

class SynchronizedLoadPolicy(TestLoadingPolicy):
    def load(self, test_model, accumulator, monitor):
        rows = TestDataKeyModel.ROWCOUNT
        half = rows // 2
        for i in range(half):
            if monitor.is_cancelled():
                return
            accumulator.append(i)
        
        initial_latch.count_down()
        try:
            finish_latch.await(2, timeunit.SECONDS)
        except threading.InterruptError as e:
            fail("Interrupted while waiting to load data")
        
        for i in range(half, rows * 2):
            if monitor.is_cancelled():
                return
            accumulator.append(i)

    def wait_for_first_half(self):
        initial_latch.await(2, timeunit.SECONDS)
    
    def wait_for_next_update(self):
        # note: this is bad design to have a method on the interface that is not 
        #       supported by all implementations.  But, it was easy, so this will alert
        #       test writers to incorrect usage of this class.
        raise UnsupportedOperationException()
    
    def finish_loading(self):
        pass

class HalfThenHalfSynchronizedLoadPolicy(SynchronizedLoadPolicy):
    def __init__(self):
        self.initial_latch = threading.CountDownLatch(1)
        self.finish_latch = threading.CountDownLatch(1)

class CyclicSynchronizedLoadPolicy(SynchronizedLoadPolicy):
    def __init__(self):
        self.waitForInitialLoadLatch = threading.CountDownLatch(1)
        self.waitForUpdateSemaphore = threading.Semaphore(-1)
        self.waitForUpdateFinishedSemaphore = threading.Semaphore(-1)

def test_incremental_loading_shows_results_before_finished():
    # clear the table
    model.clear_data()
    
    start_new_burst_load()

    wait_for_some_data()

    assert_is_loading()

def start_new_burst_load():
    model.clear_data()
    time.sleep(0.5)
    loading_policy = BurstLoadPolicy()
    model.reload()

def test_reload():
    # clear the table
    model.clear_data()
    
    start_new_burst_load()

    wait_for_some_data()

    marker_value = -1
    start_new_single_value_load_policy(marker_value)

    flush_worker()

    wait_for_some_data()

    assert_single_value(marker_value)
```

Note that Python does not have direct equivalents for Java's `Accumulator`, `TaskMonitor`, and other classes. The equivalent code in Python is written using standard libraries like threading, time, random, etc.

Also note that the original Java code has some complex logic related to loading data into a table model, which may be difficult to translate directly to Python without losing its functionality.