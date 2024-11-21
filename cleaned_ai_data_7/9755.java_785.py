from datetime import date, timezone

class DateColumnTypeMapper:
    def convert(self, value: date) -> date:
        return value.astimezone(timezone.utc).date()
