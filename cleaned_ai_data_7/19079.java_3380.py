import abc
from typing import Any, Optional

class DatabaseAdapterExtension:
    NAMESPACE = Namespace.create(type(self))
    KEY_STATICS = "static-adapters"

    class ClassDbAdapters(CloseableResource):
        def __init__(self, test_class: type) -> None:
            self.adapters = []
            connection_provider = TestConnectionProviderSource(test_class)
            try:
                external_database = AnnotationUtils.find_annotation(
                    test_class, NessieExternalDatabase
                ).orElseThrow(lambda: ValueError("Mandatory @NessieExternalDatabase missing for test class"))
                connection_provider.start()
            except Exception as e:
                raise RuntimeError(e)

        def close(self) -> None:
            if self.connection_provider is not None:
                try:
                    self.connection_provider.stop()
                finally:
                    self.connection_provider = None

    def reinit(self, adapter: DatabaseAdapter) -> None:
        adapter.reinitialize_repo("main")

    @abc.abstractmethod
    def before_all(self, context: ExtensionContext) -> None:
        test_class = context.get_required_test_class()

        class_db_adapters = (
            context.get_store(NAMESPACE)
                .get_or_compute_if_absent(KEY_STATICS, lambda k: ClassDbAdapters(test_class), type(ClassDbAdapters))
        )

        find_annotated_fields(
            test_class,
            NessieDbAdapter,
            ReflectionUtils.is_static
        ).forEach(lambda field: self.inject_field(context, field, class_db_adapters.new_database_adapter))

    @abc.abstractmethod
    def beforeEach(self, context: ExtensionContext) -> None:
        adapters = (
            context.get_store(NAMESPACE)
                .get(KEY_STATICS, type(ClassDbAdapters))
                .adapters
        )
        for adapter in adapters:
            self.reinit(adapter)

        test_instances = context.get_required_test_instances()
        all_instances = test_instances.all_instances()

        for instance in all_instances:
            find_annotated_fields(
                instance.__class__,
                NessieDbAdapter,
                ReflectionUtils.is_not_static
            ).forEach(lambda field: self.inject_field(context, field, lambda adapter: self.reinit(adapter)))

    def inject_field(self, context: ExtensionContext, field: Field, new_adapter) -> None:
        if not isinstance(field.type, (type(DatabaseAdapter), type(VersionStore))):
            raise ValueError(f"Cannot assign to {field}")

        try:
            db_adapter = AnnotationUtils.find_annotation(
                field.__class__, NessieDbAdapter
            ).orElseThrow(lambda: ValueError("Mandatory @NessieDbAdapter missing for test class"))
            database_adapter = self.create_adapter_resource(db_adapter, context)
            new_adapter(database_adapter)

            make_accessible(field).set(context.get_test_instance().get(), database_adapter)
        except Exception as e:
            raise RuntimeError(e)

    def supports_parameter(self, parameter_context: ParameterContext, extension_context) -> bool:
        return parameter_context.is_annotated(NessieDbAdapter)

    @abc.abstractmethod
    def resolve_parameter(
        self,
        parameter_context: ParameterContext,
        context: ExtensionContext,
    ) -> Any:
        pass

    @staticmethod
    def find_annotation(context, parameter_context, annotation) -> Optional[annotation]:
        opt = None
        if parameter_context is not None:
            opt = parameter_context.find_annotated(annotation)
            if opt.is_present():
                return opt
        opt = context.get_test_method().map(lambda m: AnnotationUtils.find_annotation(m, annotation))
        if opt.is_present():
            return opt
        opt = context.get_test_class().map(lambda cls: AnnotationUtils.find_annotation(cls, annotation))
        return opt

    @staticmethod
    def create_adapter_resource(adapter_annotation, context) -> DatabaseAdapter:
        factory = (
            find_annotation(context, None, NessieDbAdapterName)
                .map(NessieDbAdapterName.value)
                .map(DatabaseAdapterFactory.load_factory_by_name)
                .orElseGet(lambda: DatabaseAdapterFactory.load_factory(True))
        )

        apply_custom_config = self.extract_custom_configuration(adapter_annotation, context)

        builder = factory.new_builder()
        builder.configure(
            lambda c: SystemPropertiesConfigurer.configure_adapter_from_properties(c, property=lambda p: next((config for config in configs if (CONFIG_NAME_PREFIX + str(config.name())) == p), None))
        )
        .configure(apply_custom_config)
        .with_connector(self.get_connection_provider(context))

        return builder.build()

    @staticmethod
    def extract_custom_configuration(adapter_annotation, context) -> Any:
        apply_custom_config = lambda c: c

        if not adapter_annotation.config_method().empty():
            config_method = find_method(
                context.get_required_test_class(),
                adapter_annotation.config_method,
                AdjustableDatabaseAdapterConfig.__class__
            ).orElseThrow(lambda: ValueError(f"{NessieDbAdapter.__name__}.configMethod='{adapter_annotation.config_method}' does not exist in {context.get_required_test_class().__name__}"))

            make_accessible(config_method)

            if not Modifier.is_static(config_method.modifiers) or Modifier.is_private(
                config_method.modifiers
            ) or not DatabaseAdapterConfig.__class__.is_assignable_from(config_method.return_type):
                raise ValueError(f"{NessieDbAdapter.__name__}.configMethod='{adapter_annotation.config_method}' must have the signature 'static {DatabaseAdapterConfig.__name__} ({AdjustableDatabaseAdapterConfig.__name__))' in {context.get_required_test_class().__name__}")

            apply_custom_config = lambda c: config_method.invoke(None, c)

        return apply_custom_config

    @staticmethod
    def get_connection_provider(context) -> Any:
        connection_provider = context.get_store(NAMESPACE).get(KEY_STATICS, type(ClassDbAdapters)).connection_provider
        if connection_provider is None:
            raise ValueError("Connection provider not configured")

        return connection_provider.get_connection_provider()

    @staticmethod
    def create_store(database_adapter: DatabaseAdapter) -> VersionStore[str, str, StringStoreWorker.TestEnum]:
        return PersistVersionStore([database_adapter], StringStoreWorker.INSTANCE)

    def assert_valid_field_candidate(self, field: Field) -> None:
        if not isinstance(field.type, (type(DatabaseAdapter), type(VersionStore))):
            raise ValueError(f"Can only resolve fields of type {DatabaseAdapter.__name__} or {VersionStore.__name__}, but was: {field.type.__name__}")

        if is_private(field):
            raise ValueError(f"Field [{field}] must not be private.")

    @staticmethod
    def make_accessible(field) -> Any:
        return field

class Namespace:
    @abc.abstractmethod
    def create(self, cls: type) -> 'Namespace':
        pass

@dataclass
class TestConnectionProviderSource:
    __init__(self, test_class: type) -> None:
        self.start()  # todo implement start method

    def stop(self) -> None:
        raise NotImplementedError("stop not implemented")

    @property
    def connection_provider(self) -> Any:
        return None

@dataclass
class NessieExternalDatabase:
    __init__(self, value: str) -> None:
        pass

@dataclass
class NessieDbAdapterName:
    __init__(self, value: str) -> None:
        pass

from abc import ABCMeta, abstractmethod
import dataclasses
