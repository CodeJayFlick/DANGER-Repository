import numpy as np


class Assertions:
    RTOL = 1e-5
    ATOL = 1e-3

    def __init__(self):
        pass

    @staticmethod
    def get_default_error_message(actual, expected, message=None):
        if message is not None:
            return f"{message}\nExpected: {expected}\nActual: {actual}"
        else:
            return f"Expected: {expected}\nActual: {actual}"

    @staticmethod
    def assert_almost_equals(actual, expected, rtol=RTOL, atol=ATOL):
        if np.abs(actual - expected) > (atol + rtol * np.abs(expected)):
            raise AssertionError(Assertions.get_default_error_message(actual, expected))

    @staticmethod
    def assert_almost_equals_list(actual, expected, rtol=RTOL, atol=ATOL):
        if len(actual) != len(expected):
            raise AssertionError(
                Assertions.get_default_error_message(len(actual), len(expected), "The lists have different sizes")
            )
        for i in range(len(actual)):
            Assertions.assert_almost_equals(actual[i], expected[i], rtol, atol)

    @staticmethod
    def assert_almost_equals_array(actual, expected, rtol=RTOL, atol=ATOL):
        if not np.array_equal(actual.shape, expected.shape):
            raise AssertionError(
                Assertions.get_default_error_message(tuple(actual.shape), tuple(expected.shape),
                                                      "The shape of two arrays are different!")
            )
        for i in range(len(actual)):
            a = actual[i]
            b = expected[i]
            if np.abs(a - b) > (atol + rtol * np.abs(b)):
                raise AssertionError(f"Expected: {b} but got {a}")

    @staticmethod
    def assert_inplace_equals_array(actual, expected):
        try:
            np.testing.assert_equal(actual, expected)
        except AssertionError as e:
            raise AssertionError(Assertions.get_default_error_message(actual, expected))

    @staticmethod
    def assert_inplace_almost_equals_array(actual, expected):
        Assertions.assert_inplace_almost_equals_array(actual, expected)

    @staticmethod
    def assert_inplace_almost_equals_array_array(actual, expected, rtol=RTOL, atol=ATOL):
        try:
            np.testing.assert_allclose(actual, expected, rtol=rtol, atol=atol)
        except AssertionError as e:
            raise AssertionError(Assertions.get_default_error_message(tuple(actual.shape), tuple(expected.shape),
                                                                        "Assert Inplace failed!"))
