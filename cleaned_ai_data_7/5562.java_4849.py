class DualListingGoToService:
    def __init__(self, go_to_service, dual_listing, is_left_side):
        self.go_to_service = go_to_service
        self.dual_listing = dual_listing
        self.is_left_side = is_left_side

    def get_override_service(self):
        return self.override_service

    def go_to(self, loc):
        return self.dual_go_to(loc)

    def go_to(self, navigatable, program, address, ref_address):
        return self.dual_go_to(ProgramLocation(program, address))

    def go_to(self, loc, program):
        return self.dual_go_to(loc)

    def go_to(self, navigatable, loc, program):
        return self.dual_go_to(loc)

    def go_to(self, navigatable, address):
        return self.dual_go_to(address)

    def validate_address(self, addr):
        if addr is None:
            return False
        addresses = (
                self.is_left_side and self.dual_listing.left_addresses or 
                not self.is_left_side and self.dual_listing.right_addresses
        )
        if not addresses.contains(addr):
            self.dual_listing.set_status_info(f"\"{addr}\" is outside the current listing's view.")
            return False
        return True

    def dual_go_to(self, loc):
        if loc is None:
            return False
        if not self.validate_address(loc.address):
            return False
        panel = (
                self.is_left_side and self.dual_listing.left_panel or 
                not self.is_left_side and self.dual_listing.right_panel
        )
        return panel.go_to(loc)

    def dual_go_to(self, addr):
        if not self.validate_address(addr):
            return False
        panel = (
                self.is_left_side and self.dual_listing.left_panel or 
                not self.is_left_side and self.dual_listing.right_panel
        )
        return panel.go_to(addr)

    def go_to(self, current_address, address):
        return self.dual_go_to(address)

    def go_to(self, address):
        return self.dual_go_to(address)

    def go_to(self, address, program):
        return self.dual_go_to(address)

    def go_to_external_location(self, ext_loc, check_navigation_option):
        raise UnsupportedOperationException("Cannot Go To an external address from a dual listing view.")

    def go_to_external_location(self, navigatable, ext_loc, check_navigation_option):
        raise UnsupportedOperationException("Cannot Go To an external address from a dual listing view.")

    def go_to_query(self, from_addr, query_data, listener, monitor):
        raise UnsupportedOperationException("Go To Address or Label is not allowed in a dual listing view.")

    def set_override_service(self, override):
        self.override_service = override

    def get_default_navigatable(self):
        return self.go_to_service.get_default_navigatable()
