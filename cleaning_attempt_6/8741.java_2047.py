import ghidra_app_script as script
from ghidra.feature.vt.api.correlator.program import *
from ghidra.feature.vt.api.db.VTSessionDB import VTSessionDB
from ghidra.feature.vt.api.main import *
from ghidra.feature.vt.api.markuptype import *
from ghidra.framework.model.DomainFolder import DomainFolder
from ghidra.framework.options.ToolOptions import ToolOptions
from ghidra.framework.plugintool.PluginTool import PluginTool
from ghidra.program.model.address.AddressSet import AddressSet
from ghidra.program.model.address.AddressSetView import AddressSetView
from ghidra.program.model.listing.Program import Program

class CreateAppliedExactMatchingSessionScript(script.GhidraScript):
    def run(self) -> None:
        folder = self.askProjectFolder("Please choose a folder for the session domain object")
        name = self.askString("Please enter a Version Tracking session name", "Session Name")
        source_program = self.askProgram("Please select the source (existing annotated) program")
        destination_program = self.askProgram("Please select the destination (new) program")

        session = VTSessionDB.createVTSession(name, source_program, destination_program, self)

        folder.createFile(name, session, self.monitor())

        description = "CreateAppliedExactMatchingSession"

        session_transaction = session.startTransaction(description)
        try:
            service_provider = state.getTool()
            manager = session.getAssociationManager()

            # should we have convenience methods in VTCorrelator that don't
            # take address sets, thus implying the entire address space should be used?
            source_address_set = source_program.getMemory().getLoadedAndInitializedAddressSet()
            destination_address_set = destination_program.getMemory().getLoadedAndInitializedAddressSet()

            factory = ExactDataMatchProgramCorrelatorFactory()
            self.correlate_and_possibly_apply(source_program, destination_program, session, service_provider,
                                               manager, source_address_set, destination_address_set, factory)

            factory = ExactMatchBytesProgramCorrelatorFactory()
            self.correlate_and_possibly_apply(source_program, destination_program, session, service_provider,
                                               manager, source_address_set, destination_address_set, factory)

            factory = ExactMatchInstructionsProgramCorrelatorFactory()
            self.correlate_and_possibly_apply(source_program, destination_program, session, service_provider,
                                               manager, source_address_set, destination_address_set, factory)
        finally:
            try:
                session.endTransaction(session_transaction, True)
                destination_program.save(description, self.monitor())
                session.save(description, self.monitor())
                session.release(self)
            except CancelledException as e:
                print(f"Error: {e}")
            except VTAssociationStatusException as e:
                print(f"Error: {e}")

    def correlate_and_possibly_apply(self, source_program: Program, destination_program: Program,
                                       session: VTSession, service_provider: PluginTool,
                                       manager: VTAssociationManager, source_address_set: AddressSetView,
                                       destination_address_set: AddressSetView, factory: VTProgramCorrelatorFactory) -> None:
        restricted_source_addresses = self.exclude_accepted_matches(session, source_address_set, True)
        restricted_destination_addresses = self.exclude_accepted_matches(session, destination_address_set, False)

        options = factory.create_default_options()
        correlator = factory.create_correlator(service_provider, source_program, restricted_source_addresses,
                                               destination_program, restricted_destination_addresses, options)

        results = correlator.correlate(session, self.monitor())
        self.apply_matches(manager, results.get_matches())

    def apply_matches(self, manager: VTAssociationManager, matches: Collection[VTMatch]) -> None:
        for match in matches:
            association = match.get_association()
            association.set_accepted()

            markup_items = association.get_markup_items(self.monitor)
            for vt_markup_item in markup_items:
                self.maybe_apply_markup(association, vt_markup_item)

    def maybe_apply_markup(self, association: VTAssociation, vt_markup_item: VTMarkupItem) -> None:
        options = None

        if vt_markup_item.get_markup_type() == FunctionNameMarkupType.INSTANCE:
            try:
                vt_markup_item.apply(VTMarkupItemApplyActionType.REPLACE, options)
            except VersionTrackingApplyException as e:
                print(f"Error: {e}")

    def exclude_accepted_matches(self, session: VTSession, addr_set_view: AddressSetView,
                                  source: bool) -> AddressSet:
        if session is None:
            return new_address_set(addr_set_view)

        match_sets = session.get_match_sets()
        for match_set in match_sets:
            matches = match_set.get_matches()
            for match in matches:
                association_status = match.get_association().get_status()
                if association_status == VTAssociationStatus.ACCEPTED:
                    addr_set = new_address_set(VTMatchUtil.get_match_addresses(match, source))
                    return addr_set

        return new_address_set(addr_set_view)
