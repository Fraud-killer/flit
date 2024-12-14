from devkit import undefined


class ClientEvent:
    def __init__(self, **kwargs):
        self.client_id = kwargs.get("client_id", undefined)
        self.device_query_id = kwargs.get("device_query_id", undefined)

    def verify(self): return list()
