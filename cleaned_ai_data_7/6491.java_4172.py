import unittest

class CommentUtilsTest(unittest.TestCase):

    def test_get_comment_annotations_no_annotation(self):
        comment = "This is a comment"
        annotations = CommentUtils.get_comment_annotations(comment)
        self.assertTrue(not annotations)

    def test_get_comment_annotations_plain_annotation(self):
        comment = "This is an {@symbol symbolName}"
        annotations = CommentUtils.get_comment_annotations(comment)
        self.assertEqual(len(annotations), 1)
        word = annotations[0]
        self.assertEqual(word, "{@symbol symbolName}")

    def test_get_comment_annotations_quoted_annotation(self):
        comment = "This is an {@symbol \"symbolName\"}"
        annotations = CommentUtils.get_comment_annotations(comment)
        self.assertEqual(len(annotations), 1)
        word = annotations[0]
        self.assertEqual(word, "{@symbol \"symbolName\"}")

    def test_get_comment_annotations_quoted_annotation_with_escaped_quotes(self):
        comment = "This is an {@symbol \"symbol\\\"Name\\\"\"}"
        annotations = CommentUtils.get_comment_annotations(comment)
        self.assertEqual(len(annotations), 1)
        word = annotations[0]
        self.assertEqual(word, "{@symbol \"symbol\\\"Name\\\"\"}")

    def test_get_comment_annotations_quoted_annotation_with_braces(self):
        comment = "This is an {@symbol \"symbol{Name}\"}"
        annotations = CommentUtils.get_comment_annotations(comment)
        self.assertEqual(len(annotations), 1)
        word = annotations[0]
        self.assertEqual(word, "{@symbol \"symbol{Name}\"}")

    def test_get_comment_annotations_unquoted_annotation_with_braces(self):
        comment = "This is an {@symbol symbol{Name}}"
        annotations = CommentUtils.get_comment_annotations(comment)
        self.assertEqual(len(annotations), 1)
        word = annotations[0]
        self.assertEqual(word, "{@symbol symbol{Name}")

    def test_get_comment_annotations_unquoted_annotation_with_unbalanced_braces(self):
        comment = "This is an {@symbol symbolName}}"
        annotations = CommentUtils.get_comment_annotations(comment)
        self.assertEqual(len(annotations), 1)
        word = annotations[0]
        self.assertEqual(word, "{@symbol symbolName}")

    def test_get_comment_annotations_unquoted_annotation_with_escaped_braces(self):
        comment = "This is an {@symbol symbol\\{Name\\}}"
        annotations = CommentUtils.get_comment_annotations(comment)
        self.assertEqual(len(annotations), 1)
        word = annotations[0]
        self.assertEqual(word, "{@symbol symbol\\{Name\\}}")

if __name__ == '__main__':
    unittest.main()
