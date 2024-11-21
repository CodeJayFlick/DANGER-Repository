Here is the translation of the Java code into Python:

```Python
import re

class ProgramDatabaseSearchIteratorTest:
    def __init__(self):
        pass

    @staticmethod
    def create_search_pattern(pattern_str, case_sensitive=False):
        return re.compile(pattern_str, re.IGNORECASE if not case_sensitive else 0)

    def add_eol_comment(self, address, comment):
        # Add a EOL comment at the given address with the provided comment.
        pass

    def add_pre_comment(self, address, comment):
        # Add a pre-comment at the given address with the provided comment.
        pass

    def add_post_comment(self, address, comment):
        # Add a post-comment at the given address with the provided comment.
        pass

    @staticmethod
    def get_addr(offset):
        return offset  # Assuming this is how you would convert an offset to an Address in Python.

class ProgramLocation:
    def __init__(self, program, address):
        self.program = program
        self.address = address

class MnemonicFieldLocation(ProgramLocation):
    pass

class CommentFieldLocation(ProgramLocation):
    pass

class LabelFieldLocation(ProgramLocation):
    pass

class SearchOptions:
    def __init__(self, pattern_str, case_sensitive=False, whole_word_search=True,
                 ignore_case_insensitive_words=False, search_forward=True, 
                 max_hits_to_return=-1, return_all_matches=False):
        self.pattern = ProgramDatabaseSearchIteratorTest.create_search_pattern(pattern_str, case_sensitive)
        self.case_sensitive = case_sensitive
        self.whole_word_search = whole_word_search
        self.ignore_case_insensitive_words = ignore_case_insensitive_words
        self.search_forward = search_forward
        self.max_hits_to_return = max_hits_to_return
        self.return_all_matches = return_all_matches

class Searcher:
    def __init__(self, program, start_location, address_set=None):
        pass

    @staticmethod
    def get_next_significant_address(current_address):
        # Return the next significant address.
        pass

    @staticmethod
    def has_match(address):
        # Check if there is a match at the given address.
        return False  # Assuming this method always returns False.

    @staticmethod
    def get_match():
        # Get the current match.
        return None  # Assuming this method always returns None.

class ProgramDatabaseSearcher(Searcher):
    pass

def test_eol_comment_iterator(self):
    pattern = re.compile("XXZ*", re.IGNORECASE)
    start_location = ProgramLocation(None, self.get_addr(0x100101cL))
    searcher = CommentFieldSearcher(None, start_location, None, True, pattern)

    current_address = searcher.get_next_significant_address(None)
    assert not getNextMatch(searcher)  # Add a comment with no match.

    add_eol_comment(self.get_addr(0x1005146L), "Test EOL comments...")
    searcher = CommentFieldSearcher(None, start_location, None, True, pattern)

    current_address = searcher.get_next_significant_address(None)
    assert not getNextMatch(searcher)  # Add a comment that has no match.

    add_eol_comment(self.get_addr(0x1005d4bL), "Test something with eXXZabc")
    searcher = CommentFieldSearcher(None, start_location, None, True, pattern)

    current_address = searcher.get_next_significant_address(None)
    loc = getNextMatch(searcher)  # Add a comment that has one match.
    assert loc is not None
    assertEquals(self.get_addr(0x1005d4bL), loc.address)

def test_single_wildcard():
    add_eol_comment(self.get_addr(0x100101cL), "Test EOL comments...")
    add_eol_comment(self.get_addr(0x100101dL), "Test something with eXXZabc")
    add_eol_comment(self.get_addr(0x100101fL), "Hit found: eXXZabc followed by XXZabc")

    pattern = re.compile("*", re.IGNORECASE)
    start_location = ProgramLocation(None, self.get_addr(0x1005f53))
    searcher = CommentFieldSearcher(None, start_location, None, True, pattern)

    current_address = searcher.get_next_significant_address(None)
    loc = getNextMatch(searcher)  # Add a comment that has one match.
    assert loc is not None
    assertEquals(self.get_addr(0x1005f41), loc.address)

def test_label_matcher_iterator():
    add_label(self.get_addr(0x10018b3L), "aLABel")

    pattern = re.compile("LAB", True)
    start_location = ProgramLocation(None, self.get_addr(0x1001950))
    searcher = LabelFieldSearcher(None, start_location, None, True, pattern)

    current_address = searcher.get_next_significant_address(None)  # Add a label.
    loc = getNextMatch(searcher)  # Search for "LAB".
    assert loc is not None
    assertEquals("LaLaLABel", loc.name)
```

Note that the above Python code does not include all of the Java methods, as some were omitted in your original question.