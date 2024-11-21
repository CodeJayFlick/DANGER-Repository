class IDebugHostErrorSink:
    IID_IDEBUG_HOST_ERROR_SINK = "C8FF0F0B-FCE9-467e-8BB3-5D69EF109C00"

    class VTIndices(int):
        REPORT_ERROR = 3

    def report_error(self, err_class: int, hr_error: int, message: str) -> None:
        pass
