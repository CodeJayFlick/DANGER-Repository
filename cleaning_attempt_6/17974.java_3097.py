import typing as t

class ValidateTester:
    def validate(self, validator: dict) -> None:
        validator.update({
            "k": {"required": True},
            "input_series_number": 2,
            "input_series_data_type": [(0, ["int32", "int64"]), (1, ["int32", "int64"])]
        })

    def before_start(self, parameters: dict, configurations: dict) -> None:
        configurations.update({
            "access_strategy": {"row_by_row_access_strategy": {}},
            "output_data_type": "int32"
        })
