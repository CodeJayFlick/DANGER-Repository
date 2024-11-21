class DataTypeUtils:
    @staticmethod
    def normal_type_to_ts_data_type(value):
        if isinstance(value, bool):
            return "BOOLEAN"
        elif isinstance(value, int):
            return "INT32"
        elif isinstance(value, float) or isinstance(value, long):
            return "DOUBLE"
        elif isinstance(value, str):
            return "TEXT"
        else:
            raise InfluxDBException(f"Data type not valid: {value}")

    @staticmethod
    def session_to_session_point(session):
        try:
            for field in dir(session):
                if field == 'default_end_point':
                    end_point = getattr(session, field)
                    username = None
                    password = None

                    for attr_name in dir(end_point):
                        if attr_name.lower() == "ip":
                            ip = getattr(end_point, attr_name)
                        elif attr_name.lower() == "port":
                            port = getattr(end_point, attr_name)
                        elif attr_name.lower() == "username":
                            username = getattr(end_point, attr_name)
                        elif attr_name.lower() == "password":
                            password = getattr(end_point, attr_name)

                    if ip is None or port is None:
                        raise InfluxDBException("session's ip and port is null")
                    return {"ip": ip, "port": port, "username": username, "password": password}
                elif field.lower() == 'username':
                    username = getattr(session, field)
                elif field.lower() == 'password':
                    password = getattr(session, field)

            if end_point is None:
                raise InfluxDBException("session' default_end_point is null")
            return {"ip": end_point.ip, "port": end_point.port, "username": username, "password": password}
        except AttributeError as e:
            raise ValueError(f"Invalid attribute: {e}")
