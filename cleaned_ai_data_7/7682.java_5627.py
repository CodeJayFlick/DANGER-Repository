import unittest


class GnuDemanglerOptionsTest(unittest.TestCase):

    def test_auto_with_deprecated(self):
        options = GnuDemanglerOptions(AUTO, True)
        self.get_native_process(options)

    def test_auto_with_modern(self):
        options = GnuDemanglerOptions(AUTO, False)
        self.get_native_process(options)

    def test_gnu_with_deprecated(self):
        options = GnuDemanglerOptions(GNU, True)
        self.get_native_process(options)

    def test_gnu_with_modern(self):
        with self.assertRaises(IllegalArgumentException):
            GnuDemanglerOptions(GNU, False)

    # ... and so on for all the other methods

    def get_native_process(self, options):
        demangler_name = options.demangler_name
        application_options = options.application_arguments
        return GnuDemanglerNativeProcess(demangler_name, application_options)


class GnuDemanglerOptions:
    AUTO = 'AUTO'
    GNU = 'GNU'
    LUCID = 'LUCID'
    ARM = 'ARM'
    HP = 'HP'
    EDG = 'EDG'
    GNUV3 = 'GNUV3'
    JAVA = 'JAVA'
    GNAT = 'GNAT'
    DLANG = 'DLANG'
    RUST = 'RUST'

    def __init__(self, demangler_format, is_deprecated):
        self.demangler_name = demangler_format
        self.is_deprecated = is_deprecated

    @property
    def application_arguments(self):
        if self.is_deprecated:
            return '-deprecation'
        else:
            return ''


class GnuDemanglerNativeProcess:
    @staticmethod
    def get_demangler_native_process(demangler_name, application_options):
        # implementation of the native process method goes here
        pass

