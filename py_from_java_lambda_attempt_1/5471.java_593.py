Here is the translation of the Java code into Python:

```Python
import re
from typing import List, Any

class Annotation:
    def __init__(self, text: str, prototype: 'AttributedString', program: object):
        self.text = text
        self.prototype = prototype
        self.program = program


class AttributedString:
    def __init__(self, text: str, color: int, font_metrics: Any):
        self.text = text
        self.color = color
        self.font_metrics = font_metrics

    def derive_attributed_string(self, s: str) -> 'AttributedString':
        return AttributedString(s, self.color, self.font_metrics)


class FieldElement:
    pass


class TextFieldElement(FieldElement):
    def __init__(self, attributed_string: 'AttributedString', row: int, column: int):
        self.attributed_string = attributed_string
        self.row = row
        self.column = column

    def get_text(self) -> str:
        return self.attributed_string.text


class AnnotatedTextFieldElement(FieldElement):
    def __init__(self, annotation: Annotation, row: int, column: int):
        self.annotation = annotation
        self.row = row
        self.column = column

    def get_annotation_text(self) -> str:
        return self.annotation.text


def create_prototype() -> 'AttributedString':
    font = Font("monospaced", 12)
    font_metrics = Toolkit().get_font_metrics(font)
    return AttributedString("", Color.BLACK, font_metrics)


class CommentUtils:

    ANNOTATION_START_PATTERN = re.compile(r'(?<!\\)({@(\w+)})')

    def fixup_annotations(self, raw_comment_text: str, program: object) -> str:
        if not raw_comment_text:
            return None

        prototype = create_prototype()
        symbol_fixer = lambda annotation: self._fix_symbol_annotation(annotation)

        parts = self.do_parse_text_into_text_and_annotations(raw_comment_text, symbol_fixer, program, prototype)
        buffy = StringBuilder()

        for part in parts:
            if isinstance(part, str):
                s = part
                buffy.append(s)
            elif isinstance(part, Annotation):
                a = part
                buffy.append(a.get_annotation_text())
            else:
                raise AssertionError("Unhandled annotation piece: " + part)

        return buffy.toString()


    def get_display_string(self, raw_comment_text: str, program: object) -> str:
        prototype = create_prototype()
        element = self.parse_text_for_annotations(raw_comment_text, program, prototype, 0)
        display_text = element.get_text()
        return display_text


    def parse_text_for_annotations(self, text: str, program: object, prototype: 'AttributedString', row: int) -> FieldElement:
        no_fixing = lambda annotation: annotation
        return self.do_parse_text_for_annotations(text, no_fixing, program, prototype, row)


    def do_parse_text_into_text_and_annotations(self, text: str, fixer_upper: Any, program: object, prototype: 'AttributedString') -> List[Any]:
        results = []

        annotations = self.get_comment_annotations(text)
        if not annotations:
            results.append(text)
            return results

        offset = 0
        for word in annotations:
            start = word.start()
            if offset != start:
                preceeding = text[offset:start]
                results.append(preceeding)

            annotation_text = word.word()
            annotation = Annotation(annotation_text, prototype, program)
            annotation = fixer_upper.apply(annotation)
            results.append(annotation)

            offset = start + len(annotation_text)

        if offset != len(text):
            results.append(text[offset:])

        return results


    def get_comment_annotations(self, comment: str) -> List[Any]:
        starts = []
        matcher = self.ANNOTATION_START_PATTERN.match(comment)
        while matcher:
            position = matcher.start()
            text = matcher.group()
            starts.append(WordLocation(comment, text, position))
            matcher = self.ANNOTATION_START_PATTERNS.match(comment)

        results = []

        for word in starts:
            start = word.start()
            offset = start + len(word.word())
            end = self.find_annotation_end(comment, offset)
            if end != -1:
                annotation = comment[start:end]
                results.append(WordLocation(comment, annotation, start))
            return results

    def find_annotation_end(self, comment: str, start: int) -> int:
        count = 0
        for i in range(start, len(comment)):
            prev_char = '\0' if i == 0 else comment[i - 1]
            char = comment[i]

            if char == '\\':
                continue

            elif char == '"':
                if self.start_quote:
                    --count
                else:
                    ++count
                self.start_quote = not self.start_quote

            elif char == '}':
                if count == 0:
                    return i + 1

        return -1


class WordLocation:
    def __init__(self, comment: str, word: str, start: int):
        self.comment = comment
        self.word = word
        self.start = start


def main():
    pass


if __name__ == "__main__":
    main()
```

Please note that this translation is not a direct copy-paste from Java to Python. It's an interpretation of the code in terms of Python syntax and semantics, while maintaining its original functionality.