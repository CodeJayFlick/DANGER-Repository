Here is the translation of the Java code into Python:

```Python
import re

class UserSearchUtils:
    STAR = "*"
    GLOB_CHARACTERS = [chr(42), chr(63)]

    NON_GLOB_BACKSLASH_PATTERN = re.compile(r"\\\\(?![*?])")
    STAR_PATTERN = re.compile("(?<!\\)\\\*")
    QUESTION_PATTERN = re.compile("(?<!\\)\\?")

    CASE_SENSITIVE = 0

    @staticmethod
    def create_search_pattern(input, case_sensitive):
        options = 0 if not case_sensitive else re.IGNORECASE
        pattern = UserSearchUtils.create_pattern(input, True, options)
        return pattern

    @staticmethod
    def create_literal_search_pattern(text):
        pattern = UserSearchUtils.create_pattern(text, False, UserSearchUtils.CASE_SENSITIVE)
        return pattern

    @staticmethod
    def create_startswith_pattern(input, allow_globbing, options):
        wild_card_pattern = UserSearchUtils.create_single_star_pattern(input, allow_globbing, options)
        if wild_card_pattern is not None:
            return wild_card_pattern
        converted = UserSearchUtils.convert_user_input_to_regex(input, allow_globbing)
        pattern = re.compile(".*" + converted, options)
        return pattern

    @staticmethod
    def create_endswith_pattern(input, allow_globbing, options):
        wild_card_pattern = UserSearchUtils.create_single_star_pattern(input, allow_globbing, options)
        if wild_card_pattern is not None:
            return wild_card_pattern
        converted = UserSearchUtils.convert_user_input_to_regex(input, allow_globbing)
        pattern = re.compile(".*" + converted + ".*", options)
        return pattern

    @staticmethod
    def create_contains_pattern(input, allow_globbing, options):
        wild_card_pattern = UserSearchUtils.create_single_star_pattern(input, allow_globbing, options)
        if wild_card_pattern is not None:
            return wild_card_pattern
        converted = UserSearchUtils.convert_user_input_to_regex(input, allow_globbing)
        pattern = re.compile(".*" + converted + ".*", options)
        return pattern

    @staticmethod
    def create_pattern(input, allow_globbing, options):
        if allow_globbing and input == UserSearchUtils.STAR:
            return re.compile(".+", options)
        return None

    @staticmethod
    def convert_user_input_to_regex(input, allow_globbing):
        escaped = UserSearchUtils.escape_escape_characters(input)

        if allow_globbing:
            escaped = UserSearchUtils.escape_some_regex_characters(escaped, UserSearchUtils.GLOB_CHARACTERS)
            escaped = UserSearchUtils.convert_globbing_characters_to_regex(escaped)
        else:
            escaped = UserSearchUtils.escape_all_regex_characters(escaped)

        return escaped

    @staticmethod
    def convert_globbing_characters_to_regex(input):
        question_matcher = re.compile(UserSearchUtils.QUESTION_PATTERN.pattern).matcher(input)
        question_replaced = question_matcher.sub(".", input)

        star_matcher = re.compile(UserSearchUtils.STAR_PATTERN.pattern).matcher(question_replaced)
        return star_matcher.sub(".*?", question_replaced)

    @staticmethod
    def escape_escape_characters(input):
        backslash_matcher = re.compile(UserSearchUtils.NON_GLOB_BACKSLASH_PATTERN.pattern).matcher(input)
        return backslash_matcher.sub("\\\\", input)

    @staticmethod
    def escape_all_regex_characters(input):
        return re.escape(input)

    @staticmethod
    def escape_some_regex_characters(input, do_not_escape):
        buffy = ""
        for char in input:
            if chr(char) not in do_not_escape:
                buffy += "\\" + str(chr(char))
            else:
                buffy += str(chr(char))

        return buffy

UserSearchUtils.create_search_pattern("test", True)
```

Note: Python does not have a direct equivalent to Java's `Pattern` class, so the regular expressions are compiled using the built-in `re.compile()` function.