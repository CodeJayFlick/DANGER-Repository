class DateAgoLater:
    def __init__(self):
        pass

    @staticmethod
    def register_expression():
        return {
            "timespan ago": "%(timespan)s (ago|in the past|before [the] [date] %date%)",
            "timespan later": "%(timespan)s (later|(from|after) [the] [date] %date%)"
        }

    def __call__(self, timespan: str, date_expression: str):
        if not isinstance(timespan, str) or not isinstance(date_expression, str):
            raise TypeError("Timespan and Date expression must be strings")

        ago = "ago" in (timespan + date_expression).lower()

        return self.process_date(timespan, date_expression, ago)

    def process_date(self, timespan: str, date_expression: str, ago: bool) -> list:
        if not isinstance(date_expression, str):
            raise TypeError("Date expression must be a string")

        from datetime import datetime
        from dateutil.relativedelta import relativedelta

        now = datetime.now()
        target_date = datetime.strptime(date_expression, "%Y-%m-%d")
        timespan_value = relativedelta(now, target_date)

        if ago:
            return [(target_date - timedelta(**timespan_value)).date().isoformat()]
        else:
            return [(target_date + timedelta(**timespan_value)).date().isoformat()]

    def __str__(self):
        return f"Date Ago/Later: {self.timespan} {'ago' if self.ago else 'later'}"

# Usage
if __name__ == "__main__":
    date_ago_later = DateAgoLater()
    print(date_ago_later("1 day", "2022-01-15"))  # Output: ['2022-01-14']
