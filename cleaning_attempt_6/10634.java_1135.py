import xml.etree.ElementTree as ET

class DecisionNode:
    def __init__(self):
        self.children = []
        self.constraint = None
        self.property_map = {}

    @property
    def children(self):
        return self._children

    @children.setter
    def children(self, value):
        self._children = value

    @property
    def constraint(self):
        return self._constraint

    @constraint.setter
    def constraint(self, value):
        self._constraint = value

    @property
    def property_map(self):
        return self._property_map

    @property_map.setter
    def property_map(self, value):
        self._property_map = value


class Constraint:
    def __init__(self, name):
        self.name = name

    def is_satisfied(self, color):
        pass  # to be implemented in child classes

    def load_constraint_data(self, data):
        pass  # to be implemented in child classes

    def equals(self, other):
        return False  # default implementation for now

    def get_description(self):
        return ""  # default implementation for now


class RedColorConstraint(Constraint):
    def __init__(self):
        super().__init__("RED")

    def is_satisfied(self, color):
        return color.get_red() == self.red_value

    def load_constraint_data(self, data):
        self.red_value = int(data["VALUE"])

    def equals(self, other):
        if not isinstance(other, RedColorConstraint):
            return False
        return self.red_value == other.red_value

    def get_description(self):
        return f"Red value = {self.red_value}"


class GreenColorConstraint(Constraint):
    def __init__(self):
        super().__init__("GREEN")

    def is_satisfied(self, color):
        return color.get_green() == self.green_value

    def load_constraint_data(self, data):
        self.green_value = int(data["VALUE"])

    def equals(self, other):
        if not isinstance(other, GreenColorConstraint):
            return False
        return self.green_value == other.green_value

    def get_description(self):
        return f"Green value = {self.green_value}"


class BlueColorConstraint(Constraint):
    def __init__(self):
        super().__init__("BLUE")

    def is_satisfied(self, color):
        return color.get_blue() == self.blue_value

    def load_constraint_data(self, data):
        self.blue_value = int(data["VALUE"])

    def equals(self, other):
        if not isinstance(other, BlueColorConstraint):
            return False
        return self.blue_value == other.blue_value

    def get_description(self):
        return f"Blue value = {self.blue_value}"


class DecisionTree:
    def __init__(self):
        self.constraints = {}

    def register_constraint_type(self, name, constraint_class):
        self.constraints[name] = constraint_class

    def load_constraints(self, xml_name, is):
        root = ET.fromstring(is.read().decode("utf-8"))
        for child in root:
            if child.tag == "RED":
                red_value = int(child.get("VALUE", 0))
                blue_value = int(child.get("VALUE", 255))
                green_value = int(child.get("VALUE", 255))

                node = DecisionNode()
                constraint = self.constraints["RED"](red_value)
                property_map = {"NAME": PropertyValue(name=child.find(".//NAME").text)}
                node.constraint = constraint
                node.property_map = property_map

            elif child.tag == "BLUE":
                red_value = int(child.get("VALUE", 0))
                blue_value = int(child.get("VALUE", 255))
                green_value = int(child.get("VALUE", 255))

                node = DecisionNode()
                constraint = self.constraints["BLUE"](blue_value)
                property_map = {"NAME": PropertyValue(name=child.find(".//NAME").text)}
                node.constraint = constraint
                node.property_map = property_map

            elif child.tag == "GREEN":
                red_value = int(child.get("VALUE", 0))
                blue_value = int(child.get("VALUE", 255))
                green_value = int(child.get("VALUE", 255))

                node = DecisionNode()
                constraint = self.constraints["GREEN"](green_value)
                property_map = {"NAME": PropertyValue(name=child.find(".//NAME").text)}
                node.constraint = constraint
                node.property_map = property_map

            # add more cases for other colors as needed


class PropertyValue:
    def __init__(self, name):
        self.name = name
        self.value = None

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value


def test_tree_build():
    decision_tree = DecisionTree()
    decision_tree.register_constraint_type("BLUE", BlueColorConstraint)
    decision_tree.register_constraint_type("GREEN", GreenColorConstraint)
    decision_tree.register_constraint_type("RED", RedColorConstraint)

    constraint_xml1 = """
    <ROOT>
        <NAME>UNKNOWN</NAME>
        <RED VALUE="255">
            <BLUE VALUE="255">
                <GREEN VALUE="255">
                    <NAME>WHITE</NAME>
                </GREEN>
            </BLUE>
        </RED>
        <RED VALUE="0">
            <BLUE VALUE="0">
                <GREEN VALUE="255">
                    <NAME>YELLOW</NAME>
                </GREEN>
            </BLUE>
        </RED>
    </ROOT>
"""

    constraint_xml2 = """
    <ROOT>
        <RED VALUE="255">
            <BLUE VALUE="255">
                <GREEN VALUE="0">
                    <NAME>PURPLE</NAME>
                </GREEN>
            </BLUE>
        </RED>
        <BLUE VALUE="0">
            <RED VALUE="255">
                <GREEN VALUE="255">
                    <NAME>YELLOW2</NAME>
                </GREEN>
            </RED>
        </BLUE>
    </ROOT>
"""

    is1 = io.BytesIO(constraint_xml1.encode("utf-8"))
    decision_tree.load_constraints("ColorXML1", is1)

    is2 = io.BytesIO(constraint_xml2.encode("utf-8"))
    decision_tree.load_constraints("ColorXML2", is2)


def test_match_from_first_xml():
    c = Color(255, 0, 0)
    decision_set = decision_tree.get_decisions_set(c, "NAME")
    decisions = decision_set.get_decisions()
    assert len(decisions) == 1
    decision = decisions[0]
    assert decision.value == "WHITE"
    assert decision.description_path_string == "Red value = 255\nBlue value = 255\ngreen value = 255\n"


def test_match_from_additional_xml():
    c = Color(255, 0, 255)
    decision_set = decision_tree.get_decisions_set(c, "NAME")
    decisions = decision_set.get_decisions()
    assert len(decisions) == 1
    decision = decisions[0]
    assert decision.value == "PURPLE"
    assert decision.description_path_string == "Red value = 255\nBlue value = 255\ngreen value = 0\n"


def test_match_multiple():
    c = Color(255, 255, 0)
    decision_set = decision_tree.get_decisions_set(c, "NAME")
    decisions = decision_set.get_decisions()
    assert len(decisions) == 2
    decision1 = decisions[0]
    decision2 = decisions[1]
    assert decision1.value == "YELLOW"
    assert decision1.description_path_string == "Red value = 255\nBlue value = 0\ngreen value = 255\n"
    assert decision2.value == "YELLOW2"
    assert decision2.description_path_string == "Blue value = 0\nRed value = 255\ngreen value = 255\n"


def test_no_match_using_default():
    c = Color(100, 100, 100)
    decision_set = decision_tree.get_decisions_set(c, "NAME")
    decisions = decision_set.get_decisions()
    assert len(decisions) == 1
    decision = decisions[0]
    assert decision.value == "UNKNOWN"
    assert decision.description_path_string == ""
