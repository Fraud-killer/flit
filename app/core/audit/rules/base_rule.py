from abc import ABCMeta, abstractmethod


class BaseRule(metaclass=ABCMeta):
    def __init__(self, data, policy, provider):
        self.data = data
        self.policy = policy
        self.provider = provider

    @abstractmethod
    async def exert(self):
        pass
