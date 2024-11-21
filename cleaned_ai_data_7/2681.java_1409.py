import unittest

class LanguageTestWatcher(unittest.TestWatcher):
    def __init__(self, default_language=None):
        self.language = default_language or "TOY64_BE"

    @property
    def language(self):
        return self._language

    def starting(self, description):
        annotation = getattr(description, 'test_language', None)
        if annotation is not None:
            self._language = annotation.value

class TestLanguage:
    def __init__(self, value):
        self.value = value

if __name__ == '__main__':
    unittest.main()
