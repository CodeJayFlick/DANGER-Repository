import re

class UserSearchUtils:
    CASE_SENSITIVE = 1
    CASE_INSENSITIVE = 0

def create_contains_pattern(pattern: str, case_sensitive: int) -> re.Pattern:
    if case_sensitive == UserSearchUtils.CASE_SENSITIVE:
        return re.compile(re.escape(pattern))
    else:
        return re.compile(re.escape(pattern), flags=re.IGNORECASE)

def test_create_contains_pattern_no_wildcards():
    pattern = create_contains_pattern("bob", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("bb")
    assert pattern.match("bob")
    assert pattern.match("xbob")
    assert pattern.match("bobx")
    assert pattern.match("xxbobxx")

def test_create_contains_pattern_no_wildcards_case_sensitive():
    pattern = create_contains_pattern("Bob", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("bb")
    assert not pattern.match("bob")
    assert not pattern.match("xbob")
    assert not pattern.match("bobx")
    assert not pattern.match("xxbobxx")

    assert pattern.match("BoB")

def test_create_contains_pattern_with_only_wild_card_case_insensitive():
    pattern = create_contains_pattern("*", True, UserSearchUtils.CASE_INSENSITIVE)
    assert pattern.match("bb")
    assert pattern.match("boxb")
    assert pattern.match("bob")
    assert pattern.match("xbob")
    assert pattern.match("xxbobxx")

def test_create_contains_pattern_with_only_wild_card_case_sensitive():
    # Note: case sensitivity should not matter
    pattern = create_contains_pattern("*", True, UserSearchUtils.CASE_SENSITIVE)
    assert pattern.match("bb")
    assert pattern.match("boxb")
    assert pattern.match("bob")
    assert pattern.match("xbob")
    assert pattern.match("xxbobxx")

def test_create_contains_pattern_with_single_char_wild_card():
    pattern = create_contains_pattern("b?b", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("bb")
    assert not pattern.match("boxb")
    assert pattern.match("bob")
    assert not pattern.match("xbob")
    assert pattern.match("bobx")
    assert not pattern.match("xxbobxx")

def test_create_contains_pattern_wild_card():
    pattern = create_contains_pattern("b* b", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("b")
    assert pattern.match("bb")
    assert pattern.match("boob")
    assert pattern.match("bob")
    assert not pattern.match("xbob")
    assert not pattern.match("bobx")
    assert not pattern.match("xxbobxx")

def test_create_contains_pattern_wild_card_at_start():
    pattern = create_contains_pattern("*bob", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("b")
    assert not pattern.match("bb")
    assert not pattern.match("boob")
    assert not pattern.match("bobx")
    assert not pattern.match("xxbobxx")

    assert pattern.match("bob")
    assert pattern.match("xbob")
    assert pattern.match("xxbob")

def test_create_contains_pattern_wild_card_at_end():
    # Note: case sensitivity should not matter
    pattern = create_contains_pattern("bob*", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("b")
    assert not pattern.match("bb")
    assert not pattern.match("boob")

    assert pattern.match("bob")
    assert not pattern.match("xbob")
    assert pattern.match("xxbobx")
    assert not pattern.match("xxbobxx")

def test_create_pattern_no_wildcards():
    pattern = create_contains_pattern("bob", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("bb")
    assert pattern.match("bob")
    assert not pattern.match("xbob")
    assert not pattern.match("bobx")
    assert not pattern.match("xxbobxx")

def test_create_pattern_no_wildcards_case_sensitive():
    # Note: case sensitivity should not matter
    pattern = create_contains_pattern("bOb", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("bb")
    assert not pattern.match("bob")
    assert not pattern.match("xbob")

    assert pattern.match("bOb")

def test_create_pattern_single_wild_card_match_all():
    pattern = create_contains_pattern("*", True, UserSearchUtils.CASE_SENSITIVE)
    assert pattern.match("")
    assert pattern.match("  ")
    assert pattern.match("b")
    assert pattern.match("bb")
    assert pattern.match("boob")
    assert pattern.match("bob")

def test_create_pattern_wild_card_at_start():
    # Note: case sensitivity should not matter
    pattern = create_contains_pattern("*bob", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("b")
    assert not pattern.match("bb")
    assert not pattern.match("boob")
    assert not pattern.match("bobx")

    assert pattern.match("bob")
    assert pattern.match("xbob")
    assert pattern.match("xxbob")

def test_create_pattern_wild_card_at_end():
    # Note: case sensitivity should not matter
    pattern = create_contains_pattern("bob*", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("b")
    assert not pattern.match("bb")
    assert not pattern.match("boob")

    assert pattern.match("bob")
    assert not pattern.match("xbob")
    assert pattern.match("xxbobx")
    assert not pattern.match("xxbobxx")

def test_create_pattern_wild_card_as_literal_star():
    # Note: case sensitivity should not matter
    pattern = create_contains_pattern("*", True, UserSearchUtils.CASE_INSENSITIVE)
    assert not pattern.match("")
    assert not pattern.match("  ")
    assert not pattern.match("b")
    assert not pattern.match("bb")

    assert pattern.match("boBx")
    assert pattern.match("bobx")

def test_create_pattern_wild_card_as_literal_question():
    # Note: case sensitivity should not matter
    pattern = create_contains_pattern("?b", True, UserSearchUtils.CASE_INSENSITIVE)
    assert not pattern.match("")
    assert not pattern.match("  ")
    assert not pattern.match("b")
    assert not pattern.match("bb")

    assert pattern.match("boBx")
    assert pattern.match("bobx")

def test_create_pattern_wild_case_sensitive():
    # Note: case sensitivity should not matter
    pattern = create_contains_pattern("Bob[*", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("")
    assert not pattern.match("  ")
    assert not pattern.match("b")
    assert not pattern.match("bb")

    assert pattern.match("bob[")

def test_create_literal_exact_match_pattern():
    # A literal pattern should only match case sensitive and no globbing expansion
    pattern = create_contains_pattern("bob", True, UserSearchUtils.CASE_SENSITIVE)
    assert not pattern.match("")
    assert not pattern.match("  ")
    assert not pattern.match("b")
    assert not pattern.match("bb")

    assert pattern.match("bob")

def test_escape_all_regex_characters():
    # RegEx Special Chars: ^.$()[]+&{}*?
    escaped = re.escape("start^.$()[]+&{}*?end")
    assert escaped == "\\Qstart^.$()\\[\\]\\+\\&\\{\\}\\*\\?end\\E"

def test_escape_some_regex_characters():
    # RegEx Special Chars: ^.$()[]+&{}*?
    to_ignore = ['(', ')']
    escaped = re.escape("start^.$()[]+&{}*?end", to_ignore)
    assert escaped == "start^\\.\\$\\(\\)\\[\\]\\+\\&\\{\\}\\*\\?"

    to_ignore = ['^', '*', '?']
    escaped = re.escape("start^.$()[]+&{}*?end", to_ignore)
    assert escaped == "start^\\.\\$\\(\\)\\[\\]\\+\\&\\{\\}*\\?"
