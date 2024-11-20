import logging
from typing import List, Tuple

class NDListGenerator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def generate(args: List[str]) -> bool:
        options = get_options()
        try:
            if Arguments.has_help(args):
                print_help(options)
                return True

            parser = DefaultParser()
            cmd = parser.parse(options, args, None, False)

            input_shapes = cmd.get_option_value("input-shapes")
            output_file = cmd.get_option_value("output-file")
            ones = cmd.has_option("ones")

            path = Path(output_file)

            with NDManager() as manager:
                nd_list = []
                for pair in parse_shape(input_shapes):
                    data_type, shape = pair
                    if ones:
                        nd_list.append(manager.ones(shape, data_type))
                    else:
                        nd_list.append(manager.zeros(shape, data_type))

                with open(path, "wb") as f:
                    manager.encode(f)

            self.logger.info("NDList file created: %s", path)
            return True

        except ParseException as e:
            print_help(e.get_message(), options)

        except Exception as e:
            self.logger.error("Unexpected error", e)

        return False

    @staticmethod
    def parse_shape(shape_str: str) -> List[Tuple[DataType, Shape]]:
        input_shapes = []
        if shape_str is not None and "(" in shape_str:
            pattern = re.compile(r"\((\s*(\d+)(,[\s]+\d+)*)\)\(([sdubilBfS]?)")
            matcher = pattern.match(shape_str)
            while matcher:
                tokens = matcher.group(1).split(",")
                array = [int(token) for token in tokens]
                data_type
                if data_type is None or data_type == "":
                    data_type = DataType.FLOAT32

                input_shapes.append((data_type, Shape(array)))

        elif shape_str is not None and "," in shape_str:
            tokens = shape_str.split(",")
            array = [int(token) for token in tokens]
            input_shapes.append((DataType.FLOAT32, Shape(array)))

        return input_shapes


    @staticmethod
    def get_options() -> Options:
        options = []
        options.add_option(
            "h", help="Print this help.", has_arg=False)
        options.add_option(
            "s",
            required=True,
            long_opt="input-shapes",
            has_arg=True, arg_name="INPUT-SHAPES",
            desc="Input data shapes for the model.")
        options.add_option(
            "o",
            required=True,
            long_opt="output-file",
            has_arg=True, arg_name="OUTPUT-FILE",
            desc="Write output NDList to file.")
        options.add_option(
            "1", long_opt="ones", has_arg=False, arg_name="ones", desc="Use all ones instead of zeros.")

        return options


if __name__ == "__main__":
    generator = NDListGenerator()
    args = ["-s", "input-shapes", "-o", "output-file"]
    if not generator.generate(args):
        print("Failed to generate the file.")
