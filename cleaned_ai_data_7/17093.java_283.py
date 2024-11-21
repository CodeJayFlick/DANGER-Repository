class NoTemplateOnMNodeException(Exception):
    def __init__(self, path: str) -> None:
        message = f"NO template on {path}"
        super().__init__(message)
        self.status_code = 400
        self.is_transient_error = True

if __name__ == "__main__":
    try:
        raise NoTemplateOnMNodeException("some/path")
    except NoTemplateOnMNodeException as e:
        print(f"Error: {e}")
