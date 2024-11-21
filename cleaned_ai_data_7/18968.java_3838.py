import datetime
from typing import Type, Any

class InstantParamConverter:
    def from_string(self, instant: str) -> datetime.datetime | None:
        if not instant:
            return None
        try:
            dt = datetime.datetime.fromisoformat(instant)
            return dt.replace(tzinfo=None).astimezone(datetime.timezone.utc)
        except ValueError as e:
            raise ValueError(f"'{instant}' could not be parsed to an Instant in ISO-8601 format") from e

    def to_string(self, instant: datetime.datetime | None) -> str | None:
        if not instant:
            return None
        return instant.isoformat()

class InstantParamConverterProvider:
    def get_converter(self, raw_type: Type[Any], generic_type: Type[Any], annotations: list[Any]) -> Any | None:
        if issubclass(raw_type, datetime.datetime):
            return InstantParamConverter()
        return None

# Usage example
provider = InstantParamConverterProvider()

instant_param_converter = provider.get_converter(datetime.datetime, None, [])
if instant_param_converter and isinstance(instant_param_converter, InstantParamConverter):
    print(provider.from_string("2022-01-01T00:00:00Z"))
