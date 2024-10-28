from os import environ
from types import FunctionType

from .struct import Struct
from .checks import is_array


def variable(func):
    return ("%var%", func)


class ConfigError(Exception):
    pass


class VariableError(Exception):
    pass


class Loaders:
    def __init__(self, resolver):
        self.resolver = resolver

    def env(self, name, default=None):
        return environ.get(name, default)

    def var(self, key):
        return self.resolver.resolve(key)


class Resolver:
    def __init__(self, scope, variables):
        self.scope = scope
        self.resolved = dict()
        self.variables = variables
        self.context = Struct(load=Loaders(self))

    def resolve(self, key):
        if key not in self.resolved:
            handler = self.variables.get(key)

            if handler is None:
                failure = f"Variable {repr(key)} is not defined"
                raise ConfigError(f"{self.scope.__name__}: {failure}")

            value, errors = None, None

            try:
                value = handler(self.scope, self.context)

            except VariableError as error:

                if error.args and is_array(error.args[0]) and not any(
                    not isinstance(item, str) for item in error.args[0]
                ):
                    errors = list(error.args[0])
                
                elif error.args and isinstance(error.args[0], str):
                    errors = [error.args[0].strip()]

                else:
                    errors = [f"Has an unknown issue: {list(error.args)}"]

            self.resolved[variable] = (value, errors)

        return self.resolved[variable]


class ConfigMeta(type):
    def __new__(mcls, name, bases, attributes):
        variables = dict()

        for key, value in attributes.items():
            if (
                isinstance(value, tuple)
                and len(value) == 2
                and value[0] == "%var%"
                and isinstance(value[1], FunctionType)
                and value[1].__name__ == key
            ):
                variables[key] = value[1]

        for key in variables: del attributes[key]

        scope = type(name, bases, attributes)
        resolver = Resolver(scope, variables)
        values_dict, errors_dict = dict(), dict()

        for key in resolver.variables:
            value, errors = resolver.resolve(key)

            if errors is None: values_dict[key] = value
            else: errors_dict[key] = errors

        if errors_dict:
            raise ConfigError(f"{name}: {errors_dict}")

        return type(name, (Struct,), dict())(**values_dict)
