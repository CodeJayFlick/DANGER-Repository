class AddToSessionTask:
    def __init__(self, controller, state):
        self.controller = controller
        self.state = state

    def run(self, monitor):
        session = None
        try:
            session = self.controller.get_session()
        except Exception as e:
            print(f"Error getting session: {e}")
            return False

        source_program = session.source_program
        destination_program = session.destination_program

        exclude_accepted_matches = state.get(VTWizardStateKey.EXCLUDE_ACCEPTED_MATCHES)
        if exclude_accepted_matches is None:
            exclude_accepted_matches = False

        source_address_set_choice = state.get(VTWizardStateKey.SOURCE_ADDRESS_SET_CHOICE)
        destination_address_set_choice = state.get(VTWizardStateKey.DESTINATION_ADDRESS_SET_CHOICE)

        if source_address_set_choice is None:
            source_address_set_choice = AddressSetChoice.ENTIRE_PROGRAM
        if destination_address_set_choice is None:
            destination_address_set_choice = AddressSetChoice.ENTIRE_PROGRAM

        source_address_set_view = self.get_address_set_view(session, state,
                                                             source_address_set_choice)
        destination_address_set_view = self.get_address_set_view(session, state,
                                                                  destination_address_set_choice)

        if exclude_accepted_matches:
            source_address_set_view = self.exclude_accepted_matches(source_address_set_view, True)
            destination_address_set_view = self.exclude_accepted_matches(destination_address_set_view, False)

        service_provider = self.controller.get_tool()

        transaction_id = start_transaction(session)
        completed_successfully = False
        try:
            session.set_events_enabled(False)  # prevent table updates while busy

            correlator_factories = get_correlators(state)
            correlator_options = get_correlator_options(state)

            no_match_list = []
            for i, factory in enumerate(correlator_factories):
                correlator = factory.create_correlator(service_provider,
                                                        source_program,
                                                        source_address_set_view,
                                                        destination_program,
                                                        destination_address_set_view,
                                                        correlator_options[i])

                result_set = correlator.correlate(session, monitor)
                if result_set.match_count == 0:
                    no_match_list.append(correlator)

            if not no_match_list:
                completed_successfully = True
        except CancelledException as e:
            cause = e.cause  # CancelledException may hide more serious error

            if cause is None:
                print("Correlation canceled by user.")
            else:
                print(f"Correlation cancelled due to exception: {cause.message}")
        except Exception as e:
            print(f"Correlation cancelled due to unexpected exception: {e}")

        finally:
            session.set_events_enabled(True)
            end_transaction(session, transaction_id, completed_successfully)

    def get_address_set_view(self, session, state, choice):
        if choice == AddressSetChoice.SELECTION:
            return state.get(VTWizardStateKey.SOURCE_SELECTION)  # or DESTINATION_*
        elif choice == AddressSetChoice.MANUALLY_DEFINED:
            return state.get(VTWizardStateKey.SOURCE_ADDRESS_SET_VIEW)
        else:  # ENTIRE_PROGRAM
            if session.source_program is not None and session.destination_program is not None:
                return session.source_program.memory, session.destination_program.memory

    def exclude_accepted_matches(self, addr_set_view, source):
        session = state.get(VTWizardStateKey.EXISTING_SESSION)
        addr_set = AddressSet(addr_set_view)

        if session is not None:
            match_sets = session.match_sets
            for match_set in match_sets:
                matches = match_set.matches
                for match in matches:
                    status = match.association.status

                    if status == VTAssociationStatus.ACCEPTED:
                        addr_set.delete(VTMatchUtil.get_match_addresses(match, source))

        return addr_set

    def start_transaction(self, session):
        if isinstance(session, DomainObjectAdapterDB):
            return (session).start_transaction("Correlate")
        else:
            return -1

    def end_transaction(self, session, transaction_id, completed_successfully):
        if transaction_id == -1:
            return
        ((DomainObjectAdapterDB) session).end_transaction(transaction_id, completed_successfully)

    def get_correlator_options(self, state_key):
        return list(state_key.get(VTWizardStateKey.PROGRAM_CORRELATOR_OPTIONS_LIST))

    def get_correlators(self, state_key):
        return list(state_key.get(VTWizardStateKey.PROGRAM_CORRELATOR_FACTORY_LIST))
