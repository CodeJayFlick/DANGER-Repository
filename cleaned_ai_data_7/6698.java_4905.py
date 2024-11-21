import unittest
from io import StringIO
from xml.etree.ElementTree import ElementTree
from collections import namedtuple

class PatternInfoRowObject:
    def __init__(self, pattern_type, bit_sequence, context_register_filter):
        self.pattern_type = pattern_type
        self.bit_sequence = bit_sequence
        self.context_register_filter = context_register_filter

    @staticmethod
    def export_xml_file(rows, file_path, pre_bits_of_check, total_bits_of_check):
        # Implementation of this method is not provided in the given Java code.
        pass


class FunctionBitPatternsXmlImportExportTest(unittest.TestCase):

    def test_round_trip(self):
        rows = []

        class DittedBitSequence:
            def __init__(self, hex_string, is_alignment):
                self.hex_string = hex_string
                self.is_alignment = is_alignment

        pre_seq1 = DittedBitSequence("0x00 0x01", True)
        pattern_info_row_object_pre1 = PatternInfoRowObject(PatternType.PRE, pre_seq1, None)
        rows.append(pattern_info_row_object_pre1)

        pre_seq2 = DittedBitSequence("0x00 0x02", True)
        pattern_info_row_object_pre2 = PatternInfoRowObject(PatternType.PRE, pre_seq2, None)
        rows.append(pattern_info_row_object_pre2)

        class ContextRegisterFilter:
            def __init__(self):
                self.reg_and_values_to_filter = []

            def add_reg_and_value_to_filter(self, reg_name, value):
                self.reg_and_values_to_filter.append((reg_name, value))

        context_register_filter = ContextRegisterFilter()
        context_register_filter.add_reg_and_value_to_filter("cReg", 1)

        post_seq1 = DittedBitSequence("0x00 0x03")
        pattern_info_row_object_post1 = PatternInfoRowObject(PatternType.FIRST, post_seq1, context_register_filter)
        pattern_info_row_object_post1.alignment = 4
        rows.append(pattern_info_row_object_post1)

        post_seq2 = DittedBitSequence("0x00 0x04")
        pattern_info_row_object_post2 = PatternInfoRowObject(PatternType.FIRST, post_seq2, context_register_filter)
        pattern_info_row_object_post2.alignment = 4
        rows.append(pattern_info_row_object_post2)

        xml_file_path = "PatternInfoXML.xml"
        PatternInfoRowObject.export_xml_file(rows, xml_file_path, 16, 32)

        with open(xml_file_path) as file:
            xml_string = file.read()

        patterns = parse_pattern_pair_set(StringIO(xml_string))

        self.assertEqual(16, patterns.post_bits_of_check)
        self.assertEqual(32, patterns.total_bits_of_check)

        self.assertEqual(2, len(patterns.pre_sequences))
        for seq in patterns.pre_sequences:
            if seq.hex_string == "0x00 0x01" or seq.hex_string == "0x00 0x02":
                continue
            else:
                self.fail()

        self.assertEqual(2, len(patterns.post_patterns))
        for pat in patterns.post_patterns:
            if pat.hex_string == "0x00 0x03" or pat.hex_string == "0x00 0x04":
                self.assertNotEqual(None, pat.post_rules)
                self.assertEqual(1, len(pat.post_rules))
                self.assertTrue(isinstance(pat.post_rules[0], AlignRule))
                self.assertEqual(3, ((AlignRule) pat.post_rules[0]).align_mask)
                self.assertNotEqual(None, pat.match_actions)
            else:
                self.fail()

        has_match = False
        for match in patterns.post_patterns[0].match_actions:
            if not isinstance(match, FunctionStartAnalyzer.ContextAction):
                continue
            has_match = True
            self.assertEqual("cReg", (FunctionStartAnalyzer.ContextAction) match).name)
            self.assertEqual(1, ((FunctionStartAnalyzer.ContextAction) match).value)

        self.assertTrue(has_match)


if __name__ == "__main__":
    unittest.main()
