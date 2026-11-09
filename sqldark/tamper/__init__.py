"""Tamper scripts: transform payloads to evade filters/WAFs. sqlmap-style."""
import importlib
import pkgutil

_REGISTRY = {}


class Tamper:
    name = "base"
    description = ""

    def tamper(self, payload):
        return payload


def register(cls):
    _REGISTRY[cls.name] = cls
    return cls


def load_all():
    """Import every tamper module so decorators register the classes."""
    import sqldark.tamper.scripts as scripts_pkg
    for _, modname, _ in pkgutil.iter_modules(scripts_pkg.__path__):
        importlib.import_module(f"sqldark.tamper.scripts.{modname}")
    return _REGISTRY


def get(names):
    load_all()
    chain = []
    for n in names:
        n = n.strip()
        if not n:
            continue
        if n not in _REGISTRY:
            raise KeyError(f"unknown tamper: {n}")
        chain.append(_REGISTRY[n]())
    return chain


def available():
    load_all()
    return {n: c.description for n, c in sorted(_REGISTRY.items())}
