from devkit import undefined


class Message(dict):
    def __init__(self, *, code, text, path=None, context=dict()):
        data = dict(code=code, path=path, context=context, text=text)
        for name, value in data.items(): setattr(self, name, value)
        super().__init__(data)

    def new(self, *, path=undefined, context=undefined):
        path = self.path if path is undefined else path
        context = self.context if context is undefined else context
        return Message(code=self.code, text=self.text, path=path, context=context)
