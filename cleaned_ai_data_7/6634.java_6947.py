import os
from xml.etree import ElementTree as ET

class Patterns:
    PATTERN_FILE_NAME = "patternfile"
    DATA_PATTERNS = "data/patterns"

    @staticmethod
    def get_pattern_decision_tree():
        pattern_dirs = Application().find_module_subdirectories(Patterns.DATA_PATTERNS)
        pattern_constraint_files = find_pattern_constraint_files(pattern_dirs)
        decision_tree = ProgramDecisionTree()
        decision_tree.register_property_name(Patterns.PATTERN_FILE_NAME)
        for resource_file in pattern_constraint_files:
            try:
                decision_tree.load_constraints(resource_file)
            except Exception as e:
                Msg().show_error("Error Processing Pattern File", f"Error processing pattern file {resource_file}\n{e.message}")
        return decision_tree

    @staticmethod
    def has_pattern_files(program, decision_tree):
        decisions_set = decision_tree.get_decisions_set(program, Patterns.PATTERN_FILE_NAME)
        return not decisions_set.is_empty()

    @staticmethod
    def find_pattern_files(program, decision_tree):
        try:
            decisions_set = decision_tree.get_decisions_set(program, Patterns.PATTERN_FILE_NAME)
            values = [value for value in decisions_set.values()]
            pattern_file_list = []
            pattern_dirs = Application().find_module_subdirectories(Patterns.DATA_PATTERNS)

            for pattern_filename in values:
                pattern_file_list.append(get_pattern_file(pattern_dirs, pattern_filename))
        except Exception as e:
            raise (FileNotFoundException("can't find pattern file: " + str(e)), IOException(), XmlParseException())

    @staticmethod
    def get_pattern_file(pattern_dirs, pattern_filename):
        for dir in pattern_dirs:
            file = os.path.join(dir, pattern_filename)
            if os.path.exists(file):
                return file

        raise FileNotFoundError(f"can't find pattern file: {pattern_filename}")

    @staticmethod
    def find_pattern_constraint_files(pattern_dirs):
        pattern_constraint_files = []

        for dir in pattern_dirs:
            file_path = os.path.join(dir, "patternconstraints.xml")
            if os.path.exists(file_path):
                pattern_constraint_files.append(file_path)

        return pattern_constraint_files

class ProgramDecisionTree:
    pass
