import typing as t


class NessieNotFoundException(Exception):
    pass


def fetch(ref: str, page_size_hint: int | None, token: str) -> dict:
    # Your implementation here
    return {"ref": ref, "page_size_hint": page_size_hint, "token": token}


class PaginatedResponse(dict):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    def has_more(self) -> bool:
        # Your implementation here
        pass

    @property
    def token(self) -> str | None:
        # Your implementation here
        pass


class ResultStreamPaginator(t.Generic[R]):
    entries_from_response: t.Callable[[R], list]
    fetcher: t.Callable[[str, int | None, str], R]

    def __init__(self, entries_from_response: t.Callable[[R], list], fetcher: t.Callable[[str, int | None, str], R]):
        self.entries_from_response = entries_from_response
        self.fetcher = fetcher


def generate_stream(ref: str, page_size_hint: int | None) -> t.Iterator[t.Any]:
    first_page = fetcher(fetch=fetch, ref=ref, page_size_hint=page_size_hint, token=None)
    iterator = _ResultStreamPaginatorIterator(
        entries_from_response=self.entries_from_response,
        fetcher=self.fetcher,
        ref=ref,
        page_size_hint=page_size_hint,
        current_page=first_page
    )

    return iter(iterator)


class _ResultStreamPaginatorIterator:
    def __init__(self, entries_from_response: t.Callable[[R], list], fetcher: t.Callable[[str, int | None, str], R], ref: str, page_size_hint: int | None, current_page: dict):
        self.entries_from_response = entries_from_response
        self.fetcher = fetcher
        self.ref = ref
        self.page_size_hint = page_size_hint
        self.current_page = current_page

    def __iter__(self) -> t.Iterator[t.Any]:
        while True:
            if not self.current_page or len(self.entries_from_response(self.current_page)) == 0:
                break

            for entry in self.entries_from_response(self.current_page):
                yield entry

            token = self.current_page.get("token")
            page_size_hint = self.page_size_hint
            current_page = None

        if not self.current_page or len(self.entries_from_response(self.current_page)) == 0:
            raise NessieNotFoundException


if __name__ == "__main__":
    # Your test code here
