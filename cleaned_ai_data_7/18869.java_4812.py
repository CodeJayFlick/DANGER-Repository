import re

class Validation:
    HASH_REGEX = r'^[0-9a-fA-F]{16,64}$'
    REF_NAME_REGEX = r'^(?:[A-Za-z]((?![.])(?!.*\.[.])[A-Za-z0-9./_-])*\.{1})*$'
    REF_NAME_OR_HASH_REGEX = r'^((?:[0-9a-fA-F]{16,64})|(?:[A-Za-z]((?![.])(?!.*\.[.])[A-Za-z0-9./_-])*\.{1}))$'

    HASH_PATTERN = re.compile(HASH_REGEX)
    REF_NAME_PATTERN = re.compile(REF_NAME_REGEX)
    REF_NAME_OR_HASH_PATTERN = re.compile(REF_NAME_OR_HASH_REGEX)

    HASH_RULE = 'consist of the hex representation of 8-32 bytes'
    REF_RULE = f'start with a letter, followed by letters, digits, a ./_- character, not end with a slash, not contain ..'

    def __init__(self):
        pass

    @staticmethod
    def is_valid_reference_name(reference_name: str) -> bool:
        if reference_name is None:
            return False
        matcher = Validation.REF_NAME_PATTERN.match(reference_name)
        return matcher is not None

    @staticmethod
    def is_valid_hash(hash_value: str) -> bool:
        if hash_value is None:
            return False
        matcher = Validation.HASH_PATTERN.match(hash_value)
        return matcher is not None

    @staticmethod
    def is_valid_reference_name_or_hash(ref: str) -> bool:
        if ref is None:
            return False
        matcher = Validation.REF_NAME_OR_HASH_PATTERN.match(ref)
        return matcher is not None

    @staticmethod
    def validate_reference_name(reference_name: str) -> str:
        if Validation.is_valid_reference_name(reference_name):
            return reference_name
        raise ValueError(f"Reference name must {Validation.REF_RULE} - but was: {reference_name}")

    @staticmethod
    def validate_hash(hash_value: str) -> str:
        if Validation.is_valid_hash(hash_value):
            return hash_value
        raise ValueError(f"Hash must {Validation.HASH_RULE} - but was: {hash_value}")

    @staticmethod
    def validate_reference_name_or_hash(ref: str) -> str:
        if Validation.is_valid_reference_name_or_hash(ref):
            return ref
        raise ValueError(f"Reference name or hash must be either a reference name or hash, {Validation.REF_RULE} or {Validation.HASH_RULE} - but was: {ref}")
