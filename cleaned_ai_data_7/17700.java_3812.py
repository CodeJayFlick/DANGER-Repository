class TypeInferenceUtils:
    boolean_string_infer_type = None
    integer_string_infer_type = None
    long_string_infer_type = None
    floating_string_infer_type = None
    nan_string_infer_type = None

    def __init__(self):
        self.boolean_string_infer_type = IoTDBDescriptor.getInstance().getConfig().getBooleanStringInferType()
        self.integer_string_infer_type = IoTDBDescriptor.getInstance().getConfig().getIntegerStringInferType()
        self.long_string_infer_type = IoTDBDescriptor.getInstance().getConfig().getLongStringInferType()
        self.floating_string_infer_type = IoTDBDescriptor.getInstance().getConfig().getFloatingStringInferType()
        self.nan_string_infer_type = IoTDBDescriptor.getInstance().getConfig().getNanStringInferType()

    def is_number(self, s):
        if not s or s.lower() == "nan":
            return False
        try:
            float(s)
        except ValueError:
            return False
        return True

    def is_boolean(self, s):
        return s.lower() in [SQLConstant.BOOLEAN_TRUE, SQLConstant.BOOLEAN_FALSE]

    def is_convert_float_precision_lack(self, s):
        return int(s) > (2 << 24)

    @staticmethod
    def get_predicted_data_type(value, infer_type=False):
        if not value:
            return None

        str_value = str(value)
        
        if infer_type and isinstance(value, str):
            if is_boolean(str_value):
                return TypeInferenceUtils.boolean_string_infer_type
            elif is_number(str_value) and "." not in str_value and not str_value.startswith("0x"):
                if is_convert_float_precision_lack(str_value):
                    return TypeInferenceUtils.long_string_infer_type
                else:
                    return TypeInferenceUtils.integer_string_infer_type
            elif "null" == str_value.lower() or "NULL" == str_value.upper():
                return None
            elif "NaN" == str_value:
                return TypeInferenceUtils.nan_string_infer_type
        if isinstance(value, (bool, int)):
            if value is True:
                return TSDataType.BOOLEAN
            else:
                return TSDataType.INT64
        elif isinstance(value, float):
            return TSDataType.FLOAT

        return TSDataType.TEXT

    @staticmethod
    def get_aggr_data_type(aggr_func_name: str, data_type: TSDataType) -> TSDataType:
        if not aggr_func_name:
            raise ValueError("AggregateFunction Name must not be null")

        aggr_func_name = aggr_func_name.lower()
        
        match aggr_func_name:
            case SQLConstant.MIN_TIME | SQLConstant.MAX_TIME | SQLConstant.COUNT:
                return TSDataType.INT64
            case SQLConstant.MIN_VALUE | SQLConstant.LAST_VALUE | SQLConstant.FIRST_VALUE | SQLConstant.MAX_VALUE:
                return data_type
            case SQLConstant.AVG | SQLConstant.SUM:
                return TSDataType.DOUBLE
            case _:
                raise ValueError(f"Invalid Aggregation function: {aggr_func_name}")
