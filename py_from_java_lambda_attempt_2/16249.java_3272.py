Here is the translation of the Java code into Python:

```Python
import logging
from abc import ABCMeta, abstractmethod
from collections import defaultdict
from datetime import timedelta
from enum import Enum
from functools import total_ordering
from inspect import getmembers, isfunction
from itertools import chain
from operator import itemgetter
from os.path import join, realpath, dirname
from packaging import version as pkg_version
from re import compile as re_compile
from shutil import copyfileobj
from stat import S_IRWXU | S_IRGRP | S_IROTH
from subprocess import run as sub_run
from tempfile import NamedTemporaryFile, mkdtemp
from time import sleep

class IntegrationTest:
    def __init__(self):
        self.source = None
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def main(args=None):
        test = IntegrationTest()
        return test.run_tests(args)

    def run_tests(self, args):
        options = Arguments.get_options()
        try:
            parser = DefaultParser()
            cmd = parser.parse(options, args)
            arguments = Arguments(cmd)

            duration = timedelta(minutes=arguments.duration())
            tests = self.list_tests(arguments, IntegrationTest.__class__)
            while not duration < timedelta():
                start_time = datetime.now()

                if not self.run_tests(tests):
                    return False

                delta = (datetime.now() - start_time).total_seconds()
                duration -= timedelta(seconds=int(delta))

        except ParseException as e:
            formatter = HelpFormatter()
            formatter.set_left_padding(1)
            formatter.set_width(120)
            formatter.print_help(e.get_message(), options)

            return False
        except Exception as e:
            self.logger.error("Unexpected error", e)

            return False

    def run_tests(self, tests):
        totals = defaultdict(int)
        for test_class in tests:
            if not test_class.before_class():
                continue

            try:
                for i in range(test_class.get_test_count()):
                    result = test_class.run_test(i)
                    totals[result] += 1
            finally:
                test_class.after_class()

        total_failed = totals[TestResult.FAILED]
        total_passed = sum(1 for k, v in totals.items() if k == TestResult.SUCCESS)
        total_skipped = totals.get(TestResult.SKIPPED, 0)

        self.logger.info(f"Skipped: {total_skipped} tests")
        if total_failed > 0:
            self.logger.error(
                f"Failed {total_failed} out of {total_passed + total_failed} tests"
            )
        else:
            self.logger.info(f"Passed all {total_passed} tests")

        return not bool(total_failed)

    def list_tests(self, arguments, source):
        class_path = join(realpath(dirname(__file__)), "classes")
        if os.path.exists(class_path):
            for file in chain.from_iterable(
                [os.listdir(join(class_path, path)) for path in ["", "java"]]
            ):
                full_path = join(class_path, file)
                if not os.path.isdir(full_path) and file.endswith(".class"):
                    yield from self.list_tests(arguments, source)

        return []

    def get_tests_in_class(self, clazz):
        methods = [m[1] for m in inspect.getmembers(clazz, predicate=isfunction)]
        test_methods = []
        before_classes = []
        after_classes = []
        before_tests = []
        after_tests = []

        for method in methods:
            if issubclass(method.__class__, TestMetaClass):
                if isinstance(method, BeforeTestMetaClass):
                    before_tests.append(method)
                elif isinstance(method, AfterTestMetaClass):
                    after_tests.append(method)
                else:
                    test_methods.append(method)

        return test_methods, before_classes, after_classes, before_tests, after_tests

    def get_test_class(self, clazz):
        if not hasattr(clazz, "__name__"):
            raise Exception("Invalid class")

        methods = [m[1] for m in inspect.getmembers(clazz, predicate=isfunction)]
        test_methods = []
        before_classes = []
        after_classes = []
        before_tests = []
        after_tests = []

        for method in methods:
            if issubclass(method.__class__, TestMetaClass):
                if isinstance(method, BeforeTestMetaClass):
                    before_tests.append(method)
                elif isinstance(method, AfterTestMetaClass):
                    after_tests.append(method)
                else:
                    test_methods.append(method)

        return clazz(test_methods), before_classes, after_classes, before_tests, after_tests

    def run_test(self, method):
        if not self.before_test():
            return TestResult.FAILED

        try:
            start_time = datetime.now()
            method()

            delta = (datetime.now() - start_time).total_seconds()
            logger.info(f"Test {method.__name__} PASSED, duration: {delta:.3f}")

            return TestResult.SUCCESS
        except Exception as e:
            if self.expected_exception(method, e):
                logger.info(f"Test {method.__name__} PASSED")
                return TestResult.SUCCESS

            logger.error(f"Test {method.__name__} FAILED", e)

            return TestResult.FAILED
        finally:
            self.after_test()

    def get_test_count(self):
        return len(self.test_methods)

    @property
    def name(self):
        return self.source.__class__.__name__

class Arguments:
    def __init__(self, cmd=None):
        self.cmd = cmd

    @staticmethod
    def get_options():
        # This method should be implemented based on the actual command-line options.
        pass

    def duration(self):
        # This method should be implemented to return the test duration in minutes.
        pass

class DefaultParser:
    def parse(self, options, args=None):
        # This method should be implemented based on the actual parsing logic.
        pass

class HelpFormatter:
    def set_left_padding(self, padding):
        self.left_padding = padding

    def set_width(self, width):
        self.width = width

    def print_help(self, message, options):
        # This method should be implemented to print the help message based on the provided message and options.
        pass
```

Please note that this is a translation of Java code into Python. It may not work as expected without proper testing and debugging.