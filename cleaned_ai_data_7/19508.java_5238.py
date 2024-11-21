class BookPages:
    def __init__(self):
        self.book = None
        self.page = None

    @property
    def book(self):
        return self._book

    @book.setter
    def book(self, value):
        self._book = value

    @property
    def page(self):
        return self._page

    @page.setter
    def page(self, value):
        self._page = value

    def get(self, event=None):
        if not self.book or not isinstance(self.book, dict) or 'itemStack' not in self.book:
            return None
        
        item_stack = self.book['itemStack']
        
        if not item_stack or not isinstance(item_stack, dict) or 'meta' not in item_stack:
            return None

        meta = item_stack['meta']

        if not isinstance(meta, dict) or 'pages' not in meta:
            return None
        
        pages = meta['pages']

        if self.page and self.page.get(event):
            page_number = int(self.page.get(event))
            
            if page_number < 1 or page_number > len(pages):
                return None
            
            return [pages[page_number - 1]]
        
        else:
            return list(pages)

    def is_single(self):
        return bool(self.page)

    @property
    def return_type(self):
        return str

    def __str__(self, event=None, debug=False):
        if self.book and isinstance(self.book, dict) and 'itemStack' in self.book:
            item_stack = self.book['itemStack']
            
            if isinstance(item_stack, dict) and 'meta' in item_stack:
                meta = item_stack['meta']

                if isinstance(meta, dict) and 'pages' in meta:
                    pages = meta['pages']
                    
                    return f"book pages of {self.book}"
        else:
            return "unknown book"

    def init(self, exprs=None):
        for i, expr in enumerate(exprs):
            if not self.book and isinstance(expr, dict) and 'itemStack' in expr:
                self.book = expr
            elif not self.page and isinstance(expr, int):
                self.page = expr

if __name__ == "__main__":
    book_pages = BookPages()
