class Struct:
    def __init__(self, **attributes):
        for name, value in attributes.items():
            super().__setattr__(name, value)

    def __iter__(self):
        return iter(self.__dict__.items())

    def __str__(self):
        return f"{self.__class__.__name__}({dict(self)})"

    def __setattr__(self, *args, **kwargs):
        raise AttributeError("Cannot mutate a struct object")

    def __delattr__(self, *args, **kwargs):
        raise AttributeError("Cannot mutate a struct object")
