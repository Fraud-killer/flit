from .checks import (
    is_var_string,
    is_path_string,
    resolves_to_json,
    is_trimmed_string,
)

from . import undefined


class MezageError(Exception):
    pass


def mount_targets(messages, base_target):
    return [
        {
            **message,
            "target": (
                base_target
                if message["target"] is None
                else f"{base_target}.{message['target']}"
            ),
        }
        for message in messages
    ]


class Mezage:
    def __repr__(self):
        return f"<Mezage code={self.code} text={self.text}>"

    def __init__(self, *, code, text):
        self.code = code
        self.text = text

        invalid_arguments = dict()

        if not is_var_string(self.code):
            invalid_arguments["code"] = self.code

        if not is_trimmed_string(self.text):
            invalid_arguments["text"] = self.text

        if invalid_arguments:
            raise MezageError(f"InitError: {invalid_arguments}")

    def new(self, *, target=undefined, context=undefined):
        invalid_arguments = dict()

        if not (
            target is None
            or target is undefined
            or is_path_string(target)
        ):
            invalid_arguments["target"] = target
    
        if not (
            context is undefined
            or (
                isinstance(context, dict)
                and resolves_to_json(context)
                and not any(not is_var_string(key) for key in context)
            )
        ):
            invalid_arguments["context"] = context

        if invalid_arguments:
            raise MezageError(f"NewError: {invalid_arguments}")

        target = None if target is undefined else target
        context = dict() if context is undefined else context

        return dict(code=self.code, target=target, context=context, text=self.text)
