from devkit import undefined
from abc import ABCMeta, abstractmethod


class EventError(Exception):
    pass


class BaseEvent(metaclass=ABCMeta):
    attributes = list()

    @abstractmethod
    def verify(self, policy=None):
        pass

    def __init__(self, **kwargs):
        for attribtute in self.attributes:
            setattr(self, attribtute, kwargs.get(attribtute, undefined))

        self.extra = dict(item for item in kwargs.items() if item[0] not in self.attributes)
