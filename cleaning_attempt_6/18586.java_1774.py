import unittest
from unittest.mock import Mock

class FilterHolderTest(unittest.TestCase):

    def test_annotation_filter_registration_path_validator(self):
        lambda_context = Mock()
        
        holder = FilterHolder(UrlPathValidator(), AwsServletContext(None))
        
        self.assertTrue(holder.is_annotated())
        self.assertNotEqual(str(UrlPathValidator), str(holder.get_registration()))
        self.assertEqual("UrlPathValidator", holder.get_filter_name())
        self.assertEqual("UrlPathValidator", holder.get_registration().name)
        self.assertEqual(1, len(list(holder.get_registration().url_pattern_mappings.values())))
        self.assertEqual("/*", list(holder.get_registration().url_pattern_mappings.values())[0])

if __name__ == '__main__':
    unittest.main()
