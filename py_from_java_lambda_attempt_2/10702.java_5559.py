Here is the translation of the Java code into Python:

```Python
import unittest

class StringUtilitiesTest(unittest.TestCase):

    def test_count_occurrences_of_character(self):
        self.assertEqual(5, count_occurrences("AxBxCxDxxX", 'x'))

    def test_to_quoted_string(self):
        # single char
        self.assertEqual("'\\''", to_quoted_string([ord('\\'), ord('\'')]))
        self.assertEqual("'\"'", to_quoted_string([ord('"')]))
        self.assertEqual("'\\n'", to_quoted_string([0x0a]))
        self.assertEqual("'\\t'", to_quoted_string([0x09]))
        self.assertEqual("'a'", to_quoted_string([97]))
        self.assertEqual("'\\x04'", to_quoted_string([4]))
        self.assertEqual("'\\u0004'", to_quoted_string([0, 4], 'unicode-escape'))
        self.assertEqual("'\\U00000004'", to_quoted_string([0, 0, 0, 4], 'unicode-escape'))

        # string
        self.assertEqual("\"'a'\"", to_quoted_string("a'.encode('utf8')"))
        self.assertEqual("\"\\\"a\\\"\"", to_quoted_string('"a".encode('utf8')'))
        self.assertEqual("\"a\\nb\\tc\\x04d\"",
                         to_quoted_string("a\bn\tc\u0004d.encode('utf8')"))

    def test_convert_control_chars_to_escape_sequences(self):
        self.assertEqual("'a'", convert_control_chars_to_escape_sequences("'a'"))
        self.assertEqual("\"a\"", convert_control_chars_to_escape_sequences("\"a\""))
        self.assertEqual("a\\nb\\tc\\u0004d",
                         convert_control_chars_to_escape_sequences("a\bn\tc\u0004d"))

    def test_convert_escape_sequences_to_control_chars(self):
        self.assertEqual("'a'", convert_escape_sequences("'a'"))
        self.assertEqual("\"a\"", convert_escape_sequences("\"a\""))
        self.assertEqual("a\\nb\\tc\\u0004d", convert_escape_sequences("a\\nb\\tc\\x04d"))

    def test_ends_with_ignores_case(self):
        bob = "bob"
        endsWithBob = "endsWithBob"

        self.assertTrue(ends_with_ignores_case(endsWithBob, bob))
        self.assertTrue(ends_with_ignores_case(endsWithBob.upper(), bob))

        startsWithBob = "bobWithTrailingText"
        self.assertFalse(ends_with_ignores_case(startsWithBob, bob))

        justBob = "bOb"
        self.assertTrue(ends_with_ignores_case(justBob, bob))

    def test_index_of_word(self):
        word = "test"
        sentenceWithTest = "This is a test sentence"
        sentenceWithTestNotAsAWord = "Thisisatestsentence"

        self.assertEqual(sentenceWithTest.find(word), 10)
        self.assertEqual(sentenceWithTestNotAsAWord.find(word), -1)

    def test_is_all_blank(self):
        input_array = None
        self.assertTrue(is_all_blank(input_array))
        self.assertTrue(is_all_blank(None, None))

        self.assertFalse(is_all_blank("Hi"))
        self.assertFalse(is_all_blank("Hi", None))
        self.assertFalse(is_all_blank("Hi", "Hey"))

    def test_find_word(self):
        foundWord = "word"
        sentence = "This string has a word that we should find"

        self.assertEqual(foundWord, find_word(sentence, 18).decode('utf8'))
        self.assertEqual(foundWord, find_word(sentence, 19).decode('utf8'))
        self.assertEqual(foundWord, find_word(sentence, 21).decode('utf8'))

    def test_find_last_word_position(self):
        testString = "This is a test String"
        self.assertEqual(15, find_last_word_position(testString))

    def test_to_string(self):
        self.assertEqual("ABCD", to_string(b'\x41\x42\x43\x44').decode('utf8'))

    def test_trim(self):
        max_length = 17
        under_string = "UnderMaxString"
        result = trim(under_string, max_length)
        self.assertEqual(result.decode('utf8'), under_string)

        equalTo_max_string = "AtMaxLengthString"
        max_length = equalTo_max_string.encode('utf8').length
        result = trim(equalTo_max_string, max_length).decode('utf8')
        self.assertEqual(result, equalTo_max_string)

    def test_trim_middle(self):
        over_string = "Over By 1"
        max_length = over_string.encode('utf8').length - 2
        result = trim_middle(over_string, max_length)
        self.assertEqual("Ov...y 1", result.decode('utf8'))

    def test_get_last_word(self):
        self.assertEqual("word", get_last_word("/This/is/my/last/word", "/"))
        self.assertEqual("java", get_last_word("/This/is/my/last/word/MyFile. java", "."))

    def test_trim_trailing_nulls(self):
        self.assertEqual("", trim_trailing_nulls(b'\0\0').decode('utf8'))
        self.assertEqual("x", trim_trailing_nulls(b'x\0'.encode('utf8')).decode('utf8'))

    def test_to_lines(self):
        s = "This\nis\nmy\nString"
        lines = to_lines(s.encode('utf8'))
        self.assertEqual(4, len(lines))
        for i in range(len(lines)):
            if i == 3:
                self.assertEqual("String", lines[i].decode('utf8'))
            else:
                self.assertEqual(["This", "is", "my"][i], lines[i].decode('utf8'))

    def test_to_lines_newline_at_beginning_middle_and_end(self):
        s = "\nThis\nis\nmy\nString\n"
        lines = to_lines(s.encode('utf8'))
        self.assertEqual(6, len(lines))
        for i in range(len(lines)):
            if i == 0:
                self.assertEqual("", lines[i].decode('utf8'))
            elif i == 5:
                self.assertEqual("", lines[i].decode('utf8'))
            else:
                self.assertEqual(["This", "is", "my", "String"][i-1], lines[i].decode('utf8'))

    def test_to_lines_preserve_tokens(self):
        s = "My\n\nString"
        lines = to_lines(s.encode('utf8'), True)
        self.assertEqual(3, len(lines))
        for i in range(len(lines)):
            if i == 0:
                self.assertEqual("My", lines[i].decode('utf8'))
            elif i == 1:
                self.assertEqual("", lines[i].decode('utf8'))
            else:
                self.assertEqual("String", lines[i].decode('utf8'))

    def test_to_lines_dont_preserve_tokens(self):
        s = "My\n\nString"
        lines = to_lines(s.encode('utf8'), False)
        self.assertEqual(2, len(lines))
        for i in range(len(lines)):
            if i == 0:
                self.assertEqual("My", lines[i].decode('utf8'))
            else:
                self.assertEqual("String", lines[i].decode('utf8'))

    def test_contains_all_ignores_case(self):
        source = "This is my source String"
        self.assertTrue(contains_all_ignores_case(source, "This"))
        self.assertTrue(contains_all_ignores_case(source.lower(), "this"))

        self.assertFalse(contains_all_ignores_case(source, "missing"))
        self.assertTrue(contains_any_ignores_case(source, ["string", "source", "my", "is"]))

    def test_contains_any_ignores_case(self):
        source = "This is my source String"
        self.assertTrue(contains_any_ignores_case(source, "This"))
        self.assertTrue(contains_any_ignores_case(source.lower(), "this"))

        self.assertFalse(contains_any_ignores_case(source, "missing"))
        self.assertTrue(contains_any_ignores_case(source, ["string", "source", "my", "is"]))

if __name__ == '__main__':
    unittest.main()
```

Please note that Python's `unittest` module is used for testing.