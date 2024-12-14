class Message(dict):
    def __init__(self, *, code, text, path=None, context=dict()):
        data = dict(code=code, path=path, context=context, text=text)
        for name, value in data.items(): setattr(self, name, value)
        super().__init__(data)
