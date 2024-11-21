class OrcOfficer:
    def __init__(self, handler):
        super().__init__(handler)

    def handle_request(self, req):
        if req.request_type == 'TORTURE_PRISONER':
            self.print_handling(req)
            req.mark_handled()
        else:
            super().handle_request(req)

    def __str__(self):
        return "Orc officer"
