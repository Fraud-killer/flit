class Message(dict):
    def __init__(self, *, code, text, path=None, context=dict()):
        data = dict(code=code, text=text, path=path, context=context)
        for name, value in data.items(): setattr(self, name, value)
        super().__init__(data)
