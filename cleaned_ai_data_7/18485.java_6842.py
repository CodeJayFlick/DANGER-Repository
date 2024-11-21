class PropHelper:
    input_matrix_data_size = 6

    @staticmethod
    def to_matrix_data(value: ReadableArray, s_raw_matrix: list[float], m_scale: float) -> int:
        from_size = value.size()
        if from_size != PropHelper.input_matrix_data_size:
            return from_size
        
        for i in range(PropHelper.input_matrix_data_size):
            if i % 2 == 0:
                s_raw_matrix[i] = float(value.get_double(i // 2))
            else:
                s_raw_matrix[i] = (float(value.get_double((i - 1) // 2)) * m_scale)
        
        return PropHelper.input_matrix_data_size

    @staticmethod
    def from_relative(length: str, relative: float, scale: float, font_size: float) -> float:
        length = length.strip()
        string_length = len(length)

        if not length or length == "normal":
            return 0.0
        
        percent_index = string_length - 1

        if length[percent_index] == '%':
            return (float(length[:percent_index]) / 100) * relative
        else:
            two_letter_unit_index = string_length - 2
            
            if two_letter_unit_index > 0:
                last_two = length[two_letter_unit_index:]
                
                end = two_letter_unit_index
                
                unit = 1.0

                for i in range(len(last_two)):
                    if last_two[i:i+2] == "px":
                        break
                    elif last_two[i:i+2] in ["em", "ex", "ch"]:
                        unit = font_size
                        end -= 2
                        break
                    elif last_two[i:i+3] in ["pt", "pc", "mm", "cm", "in"]:
                        if last_two == "1pt":
                            unit = 1.25
                        elif last_two == "1pc":
                            unit = 15
                        elif last_two == "1mm":
                            unit = 3.543307
                        elif last_two == "1cm":
                            unit = 35.43307
                        elif last_two == "1in":
                            unit = 90
                        
                        end -= len(last_two)
                        break
                
                return float(length[:end]) * unit * scale
            else:
                return float(length) * scale

    @staticmethod
    def from_relative_svg_length(length: SVGLength, relative: float, offset: float, scale: float, font_size: float) -> float:
        if length is None:
            return offset
        
        unit_type = length.unit
        value = length.value
        unit = 1.0

        for i in range(len(SVGLength.UnitType)):
            if unit_type == SVGLength.UnitType[i]:
                break
            elif unit_type == SVGLength.UnitType[-1]:
                return (value * scale) + offset
        
        if unit_type == SVGLength.UnitType[SVGLength.UnitType.index("EMS")]:
            unit = font_size
        elif unit_type in ["EXS", "CH"]:
            unit = font_size / 2.0
        elif unit_type in ["CM", "MM", "IN", "PT", "PC"]:
            if unit_type == SVGLength.UnitType[SVGLength.UnitType.index("1pt")]:
                unit = 1.25
            elif unit_type == SVGLength.UnitType[SVGLength.UnitType.index("1pc")]:
                unit = 15
            elif unit_type == SVGLength.UnitType[SVGLength.UnitType.index("1mm")]:
                unit = 3.543307
            elif unit_type == SVGLength.UnitType[SVGLength.UnitType.index("1cm")]:
                unit = 35.43307
            elif unit_type == SVGLength.UnitType[SVGLength.UnitType.index("1in")]:
                unit = 90
        
        return (value * scale) + offset

class ReadableArray:
    def __init__(self, value):
        self.value = value
    
    @property
    def size(self):
        return len(self.value)

    def get_double(self, index: int):
        return float(self.value[index])

class SVGLength:
    UnitType = ["NUMBER", "PX", "PERCENTAGE", "EMS", "EXS", "CM", "MM", "IN", "PT", "PC"]
