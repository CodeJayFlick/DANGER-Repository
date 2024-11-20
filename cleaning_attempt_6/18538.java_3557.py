class FilterChainManager:
    PATH_PART_SEPARATOR = "/"

    def __init__(self, servlet_context):
        self.servlet_context = servlet_context
        self.filter_cache = {}
        self.filters_size = -1

    def get_filter_chain(self, request: 'HttpServletRequest', servlet) -> 'FilterChainHolder':
        target_path = request.get_request_uri()
        dispatcher_type = request.get_dispatcher_type()

        if (self.get_filters().size() == self.filters_size and
                self.filter_cache.get((dispatcher_type, target_path)) is not None):
            return self.filter_chain_cache[request]

        aws_servlet_registration = next(
            (registration for registration in self.servlet_context.get_servlet_registrations()
             if registration.get_servlet() == servlet), None)

        filter_chain_holder = FilterChainHolder()

        filters = self.get_filters()
        if not filters:
            if aws_servlet_registration is not None:
                filter_chain_holder.add_filter(FilterHolder(servlet_execution_filter(aws_servlet_registration), self.servlet_context))
            return filter_chain_holder

        for registration, holder in filters.items():
            if dispatcher_type and dispatcher_type not in registration.get_dispatcher_types():
                continue
            for path in registration.get_url_pattern_mappings():
                if self.path_matches(target_path, path):
                    filter_chain_holder.add_filter(holder)

            if aws_servlet_registration is not None:
                filter_chain_holder.add_filter(FilterHolder(servlet_execution_filter(aws_servlet_registration), self.servlet_context))

        self.put_filter_chain_cache((dispatcher_type, target_path), filter_chain_holder)
        if self.filters_size != len(filters):
            self.filters_size = len(filters)

        return filter_chain_holder

    def get_filter_chain_cache(self, dispatcher_type: DispatcherType, target_path: str) -> 'FilterChainHolder':
        key = (dispatcher_type, target_path)
        if not self.filter_cache.get(key):
            return None
        return FilterChainHolder(list(self.filter_cache[key]))

    def put_filter_chain_cache(self, key: tuple, filter_chain_holder: 'FilterChainHolder'):
        self.filter_cache[key] = list(filter_chain_holder)

    @staticmethod
    def path_matches(target_path: str, mapping: str) -> bool:
        if target_path.lower() == mapping.lower():
            return True

        parts_target = target_path.split(FilterChainManager.PATH_PART_SEPARATOR)
        parts_mapping = mapping.split(FilterChainManager.PATH_PART_SEPARATOR)

        for i in range(len(parts_target)):
            if len(parts_mapping) < i + 1 or not (parts_target[i].lower() == parts_mapping[i].lower()):
                return False

        return True


class TargetCacheKey:
    def __init__(self):
        self.target_path = None
        self.dispatcher_type = None

    @staticmethod
    def from_request(request: 'HttpServletRequest') -> 'TargetCacheKey':
        key = TargetCacheKey()
        if request.get_target_path():
            key.set_target_path(request.get_target_path())
        else:
            key.set_target_path("/")
        if request.get_dispatcher_type() is not None:
            key.set_dispatcher_type(request.get_dispatcher_type())

        return key

    def set_target_path(self, target_path: str):
        self.target_path = target_path

    def set_dispatcher_type(self, dispatcher_type: DispatcherType):
        self.dispatcher_type = dispatcher_type


class FilterChainHolder(list):
    pass


class ServletExecutionFilter:
    def __init__(self, aws_servlet_registration: AwsServletRegistration):
        self.config = None
        self.handler_servlet = aws_servlet_registration.get_servlet()
        self.initialized = False

    @staticmethod
    def from_aws_servlet_registration(aws_servlet_registration: AwsServletRegistration) -> 'ServletExecutionFilter':
        return ServletExecutionFilter(aws_servlet_registration)

    def init(self, filter_config):
        if not self.initialized:
            self.config = filter_config
            self.handler_servlet.init(self.handler_servlet.get_config())
            self.initialized = True

    @staticmethod
    def do_filter(servlet_request: 'ServletRequest', servlet_response: 'ServletResponse', filter_chain) -> None:
        pass


class FilterHolder(list):
    pass
