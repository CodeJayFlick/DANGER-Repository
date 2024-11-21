import os
import random

class TestConstant:
    BASE_OUTPUT_PATH = "target" + os.sep
    PARTIAL_PATH_STRING = "%s{}{}/{}"
    TEST_TSFILE_PATH = BASE_OUTPUT_PATH + "testTsFile" + os.sep + PARTIAL_PATH_STRING.format("", 0, 0)

    FLOAT_MIN_DELTA = 1e-5
    DOUBLE_MIN_DELTA = 1e-5

    @classmethod
    def get_random(cls):
        return random.Random(os.urandom(4)).randint(0, 2**31 - 1)
