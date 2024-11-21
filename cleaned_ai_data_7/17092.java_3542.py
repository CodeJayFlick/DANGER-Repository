class MNodeTypeMismatchException(Exception):
    def __init__(self, path: str, expected_type: int) -> None:
        super().__init__(
            f"MNode [{path}] is not a {MetadataConstant.get_m_node_type_name(expected_type)}"
        )
