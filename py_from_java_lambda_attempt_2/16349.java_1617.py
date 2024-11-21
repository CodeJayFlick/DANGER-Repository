Here is the translation of the Java code into Python:

```Python
import time
from typing import List

class ConceptMotorBulkRead:
    def __init__(self):
        self.TEST_CYCLES = 500
        self.m1 = None
        self.e1 = None
        self.v1 = None
        self.m2 = None
        self.e2 = None
        self.v2 = None
        self.m3 = None
        self.e3 = None
        self.v3 = None
        self.m4 = None
        self.e4 = None
        self.v4 = None

    def run_op_mode(self):
        cycles = 0
        timer = time.time()

        print("Press play to start tests")
        input()
        while True:
            if not opmodeIsActive():
                break

            e1, v1 = m1.read_position_velocity()
            e2, v2 = m2.read_position_velocity()
            e3, v3 = m3.read_position_velocity()
            e4, v4 = m4.read_position_velocity()

            # Put Control loop action code here.

        t1 = (time.time() - timer) / cycles

    def display_cycle_times(self):
        print("Testing: Press play to start tests")
        input()
        while True:
            if not opmodeIsActive():
                break
            self.run_op_mode()
            time.sleep(0.5)
            print(f"Test 1 of 3 (Wait for completion)")
            t2 = (time.time() - timer) / cycles

    def run_test_cycles(self):
        all_hubs = [hub for hub in hardware_map.values()]
        for module in all_hubs:
            module.set_bulk_caching_mode(LynxModule.BulkCachingMode.AUTO)

        timer.reset()
        cycles = 0
        while True:
            if not opmodeIsActive():
                break

            e1, v1 = m1.read_position_velocity()   # Uses 1 bulk-read for all 4 encoder/velocity reads,
            e2, v2 = m2.read_position_velocity()   # but don't do any `get` operations more than once per cycle.
            e3, v3 = m3.read_position_velocity()
            e4, v4 = m4.read_position_velocity()

            t1 = (time.time() - timer) / cycles
            print(f"Test 2 of 3 (Wait for completion)")
            time.sleep(0.5)

    def run_manual_cache_mode(self):
        all_hubs = [hub for hub in hardware_map.values()]
        for module in all_hubs:
            module.set_bulk_caching_mode(LynxModule.BulkCachingMode.MANUAL)

        timer.reset()
        cycles = 0
        while True:
            if not opmodeIsActive():
                break

            # Important Step 4: If you are using MANUAL mode, you must clear the BulkCache once per control cycle
            for module in all_hubs:
                module.clear_bulk_cache()

            e1, v1 = m1.read_position_velocity()    # Uses 1 bulk-read to obtain ALL the motor data
            e2, v2 = m2.read_position_velocity()
            e3, v3 = m3.read_position_velocity()
            e4, v4 = m4.read_position_velocity()

            t3 = (time.time() - timer) / cycles
            print(f"Test 3 of 3 (Wait for completion)")
            time.sleep(0.5)

    def display_cycle_times(self):
        print("Complete")
```

Note: This Python code is not a direct translation from the Java code, but rather an equivalent implementation in Python. The original Java code has been modified to fit into the structure of a typical Python program.