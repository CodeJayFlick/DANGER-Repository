Here is the translation of the Java code into Python:

```Python
import xml.etree.ElementTree as ET
from collections import defaultdict
from io import StringIO
from typing import Dict, List

class PCodeTestCombinedTestResults:
    FILENAME = "pcode_test_results"
    XML_VERSION = "1"

    def __init__(self, reports_dir: str, read_existing: bool) -> None:
        self.xml_file = f"{reports_dir}/{FILENAME}.xml"
        self.html_file = f"{reports_dir}/{FILENAME}.html"
        if read_existing and self.xml_file.exists():
            self.restore_from_xml()

    def get_test_results(self, j_unit_name: str, create_if_missing: bool) -> Dict:
        test_results = self.combined_results.get(j_unit_name)
        if test_results is None and create_if_missing:
            test_results = PCodeTestResults(j_unit_name)
            self.combined_results[j_unit_name] = test_results
        return test_results

    def restore_from_xml(self) -> None:
        try:
            tree = ET.parse(self.xml_file)
            root = tree.getroot()
            if not "PCODE_TESTS" == root.tag or XML_VERSION != root.attrib["VERSION"]:
                return
            for child in root.findall("PCodeTestResults"):
                test_results = PCodeTestResults(child)
                self.combined_results[test_results.junit_name] = test_results
        except ET.ParseError as e:
            raise IOException(f"Invalid P-Code test results xml file: {self.xml_file}", e)

    def save_to_xml(self) -> None:
        try:
            root = ET.Element("PCODE_TESTS")
            root.set("VERSION", XML_VERSION)
            for j_unit_name, test_results in self.combined_results.items():
                for group_test_name in test_results.group_test_names:
                    child = ET.SubElement(root, "PCodeTestResults")
                    child.set("JUNIT_NAME", j_unit_name)
                    child.text = str(test_results.pass_count) + "/" + str(test_results.fail_count) + "/" + str(
                        test_results.call_other_count
                    )
        except Exception as e:
            raise IOException(f"Failed to save P-Code test results xml file: {self.xml_file}", e)

    def copy_resource_file(self, resource_name: str, writer: StringIO) -> None:
        with open(resource_name, "r") as f:
            while True:
                line = f.readline()
                if not line:
                    break
                writer.write(line)
        writer.flush()

    def write_table_header(self, writer: StringIO, group_names: List[str], all_test_names_by_group: Dict) -> None:
        for i, group_name in enumerate(group_names):
            named_test_columns = all_test_names_by_group[group_name]
            for named_test_column in named_test_columns:
                column_width = named_test_column.column_width
                writer.write(f"<td class=\"ResultHead\" align=\"center\" valign=\"bottom\">")
                writer.write("<img src=\"X\" border=0 height=1 width={}> <br>".format(column_width))
                writer.write("<div class=\"r90\">{}</div></td>".format(named_test_column.test_name))
            writer.write("</tr><tr>")
        for i, group_name in enumerate(group_names):
            named_test_columns = all_test_names_by_group[group_name]
            writer.write(f"<td class=\"GroupHead\" valign=\"middle\" colspan={len(named_test_columns)}> &nbsp;")
            if len(group_name) != 0:
                writer.write(HTMLUtilities.friendly_encode_html(group_name))
        writer.write("</tr>")

    def write_result_count(self, writer: StringIO, count: int, color: str) -> None:
        if count == 0:
            writer.write("<font color=\"gray\">-</font>")
        else:
            writer.write(f"<font color={color}>{count}</font>/")
        return

    def write_test_summary_row(self, writer: StringIO, test_results: PCodeTestResults, shaded: bool) -> None:
        if shaded:
            shade_style = " class=\"shade\""
        else:
            shade_style = ""
        writer.write(f"<tr{shade_style}>")

        writer.write("  <td class=\"TestName\"><a href='../logs/{test_results.junit_name}.log' target='_log'>{}</a></td><td class=\"DateTime\">".format(
            test_results.junit_name, 
            HTMLUtilities.friendly_encode_html(test_results.time)
        ))

        if test_results.summary_has_ingest_errors or test_results.summary_has_relocation_errors or test_results.summary_has_disassembly_errors:
            writer.write("<td align='center' class='ResultSummary bad'>")
            if test_results.summary_has_ingest_errors:
                writer.write("<font color=\"red\">Ingest-Err</font><br>")
            if test_results.summary_has_relocation_errors:
                writer.write("<font color=\"red\">Reloc-Err</font><br>")
            if test_results.summary_has_disassembly_errors:
                writer.write("<font color=\"red\">Dis-Err</font>")
        else:
            summary_highlight = self.get_summary_highlight_color_class(test_results)
            writer.write(f"<td align='center' class='ResultSummary {summary_highlight}'>")
            writer.write(str(test_results.summary_pass_count) + "/" + str(test_results.summary_fail_count) + "/")

    def get_summary_highlight_color_class(self, test_results: PCodeTestResults) -> str:
        fail_count = test_results.summary_fail_count
        if not test_results.had_severe_failure and (test_results.summary_total_asserts != 0):
            return "bad"
        else:
            return ""

    def write_test_results_row(self, writer: StringIO, group_names: List[str], all_test_names_by_group: Dict, 
                               test_results: PCodeTestResults, shaded: bool, first_row: bool) -> None:
        if shaded:
            shade_style = " class=\"shade\""
        else:
            shade_style = ""
        writer.write(f"<tr{shade_style}>")

        for group_name in group_names:
            named_test_columns = all_test_names_by_group[group_name]
            for named_test_column in named_test_columns:
                test_name = named_test_column.test_name
                pass_count = test_results.get_pass_result(group_name, test_name)
                fail_count = test_results.get_fail_result(group_name, test_name)
                call_other_count = test_results.get_call_other_result(group_name, test_name)
                total_asserts = test_results.get_total_asserts(group_name, test_name)

                severe_failure = test_results.had_severe_failure(group_name, test_name)

                highlight_bad = not severe_failure and (total_asserts != 0) and (total_asserts != pass_count + fail_count + call_other_count)
                
                writer.write(f"<td align='center' class=\"Result{(' bad' if highlight_bad else '')}\">")
                if first_row:
                    writer.write("<img src=\"X\" border=0 height=1 width={}> <br>".format(named_test_column.column_width))
                if severe_failure:
                    writer.write("<font color=\"red\">ERR</font>")
                elif total_asserts == 0:
                    writer.write("<font color=\"gray\">-</font>")
                else:
                    writer.write(str(pass_count) + "/" + str(fail_count) + "/")
        writer.write("</tr>")

    def save_to_html(self) -> None:
        try:
            root = ET.Element("PCODE_TESTS")
            for j_unit_name, test_results in self.combined_results.items():
                for group_test_name in test_results.group_test_names:
                    child = ET.SubElement(root, "PCodeTestResults")
                    child.set("JUNIT_NAME", j_unit_name)
                    child.text = str(test_results.pass_count) + "/" + str(test_results.fail_count) + "/" + str(
                        test_results.call_other_count
                    )
        except Exception as e:
            raise IOException(f"Failed to save P-Code test results xml file: {self.xml_file}", e)

    def write_table_header(self, writer: StringIO, group_names: List[str], all_test_names_by_group: Dict) -> None:
        for i, group_name in enumerate(group_names):
            named_test_columns = all_test_names_by_group[group_name]
            for named_test_column in named_test_columns:
                column_width = named_test_column.column_width
                writer.write(f"<td class=\"ResultHead\" align=\"center\" valign=\"bottom\">")
                writer.write("<img src=\"X\" border=0 height=1 width={}> <br>".format(column_width))
                writer.write("<div class=\"r90\">{}</div></td>".format(named_test_column.test_name))
            writer.write("</tr><tr>")
        for i, group_name in enumerate(group_names):
            named_test_columns = all_test_names_by_group[group_name]
            writer.write(f"<td class=\"GroupHead\" valign=\"middle\" colspan={len(named_test_columns)}> &nbsp;")
            if len(group_name) != 0:
                writer.write(HTMLUtilities.friendly_encode_html(group_name))
        writer.write("</tr>")

    def write_result_count(self, writer: StringIO, count: int, color: str) -> None:
        if count == 0:
            writer.write("<font color=\"gray\">-</font>")
        else:
            writer.write(f"<font color={color}>{count}</font>/")
        return

    def write_test_summary_row(self, writer: StringIO, test_results: PCodeTestResults, shaded: bool) -> None:
        if shaded:
            shade_style = " class=\"shade\""
        else:
            shade_style = ""
        writer.write(f"<tr{shade_style}>")

        writer.write("  <td class=\"TestName\"><a href='../logs/{test_results.junit_name}.log' target='_log'>{}</a></td><td class=\"DateTime\">".format(
            test_results.junit_name, 
            HTMLUtilities.friendly_encode_html(test_results.time)
        ))

        if test_results.summary_has_ingest_errors or test_results.summary_has_relocation_errors or test_results.summary_has_disassembly_errors:
            writer.write("<td align='center' class='ResultSummary bad'>")
            if test_results.summary_has_ingest_errors:
                writer.write("<font color=\"red\">Ingest-Err</font><br>")
            if test_results.summary_has_relocation_errors:
                writer.write("<font color=\"red\">Reloc-Err</font><br>")
            if test_results.summary_has_disassembly_errors:
                writer.write("<font color=\"red\">Dis-Err</font>")
        else:
            summary_highlight = self.get_summary_highlight_color_class(test_results)
            writer.write(f"<td align='center' class='ResultSummary {summary_highlight}'>")
            writer.write(str(test_results.summary_pass_count) + "/" + str(test_results.summary_fail_count) + "/")

    def get_summary_highlight_color_class(self, test_results: PCodeTestResults) -> str:
        fail_count = test_results.summary_fail_count
        if not test_results.had_severe_failure and (test_results.summary_total_asserts != 0):
            return "bad"
        else:
            return ""

    def write_test_results_row(self, writer: StringIO, group_names: List[str], all_test_names_by_group: Dict, 
                               test_results: PCodeTestResults, shaded: bool, first_row: bool) -> None:
        if shaded:
            shade_style = " class=\"shade\""
        else:
            shade_style = ""
        writer.write(f"<tr{shade_style}>")

        for group_name in group_names:
            named_test_columns = all_test_names_by_group[group_name]
            for named_test_column in named_test_columns:
                test_name = named_test_column.test_name
                pass_count = test_results.get_pass_result(group_name, test_name)
                fail_count = test_results.get_fail_result(group_name, test_name)
                call_other_count = test_results.get_call_other_result(group_name, test_name)
                total_asserts = test_results.get_total_asserts(group_name, test_name)

                severe_failure = test_results.had_severe_failure(group_name, test_name)

                highlight_bad = not severe_failure and (total_asserts != 0) and (total_asserts != pass_count + fail_count + call_other_count)
                
                writer.write(f"<td align='center' class=\"Result{(' bad' if highlight_bad else '')}\">")
                if first_row:
                    writer.write("<img src=\"X\" border=0 height=1 width={}> <br>".format(named_test_column.column_width))
                if severe_failure:
                    writer.write("<font color=\"red\">ERR</font>")
                elif total_asserts == 0:
                    writer.write("<font color=\"gray\">-</font>")
                else:
                    writer.write(str(pass_count) + "/" + str(fail_count) + "/")
        writer.write("</tr>")

    def save_to_xml(self, file_name: str) -> None:
        try:
            root = ET.Element("PCODE_TESTS")
            for j_unit_name, test_results in self.combined_results.items():
                for group_test_name in test_results.group_test_names:
                    child = ET.SubElement(root, "PCodeTestResults")
                    child.set("JUNIT_NAME", j_unit_name)
                    child.text = str(test_results.pass_count) + "/" + str(test_results.fail_count) + "/" + str(
                        test_results.call_other_count
                    )
        except Exception as e:
            raise IOException(f"Failed to save P-Code test results xml file: {file_name}", e)

    def write_table_header(self, writer: StringIO, group_names: List[str], all_test_names_by_group: Dict) -> None:
        for i, group_name in enumerate(group_names):
            named_test_columns = all_test_names_by_group[group_name]
            for named_test_column in named_test_columns:
                column_width = named_test_column.column_width
                writer.write(f"<td class=\"ResultHead\" align=\"center\" valign=\"bottom\">")
                writer.write("<img src=\"X\" border=0 height=1 width={}> <br>".format(column_width))
                writer.write("<div class=\"r90\">{}</div></td>".format(named_test_column.test_name))
            writer.write("</tr><tr>")
        for i, group_name