import sys
import os
import pkgutil
import importlib
import importlib.util
import inspect
import random
import string
import traceback
import json
from datetime import datetime

# Lightweight forensic decorator import (file forensic.py is included)
try:
    from forensics import forensic_wrap
except Exception:
    def forensic_wrap(f):
        return f

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(PROJECT_ROOT, "artifacts", "fuzz_reports")
os.makedirs(REPORT_DIR, exist_ok=True)

def rand_int():
    return random.randint(-100000, 100000)

def rand_float():
    return random.uniform(-1e6, 1e6)

def rand_str():
    length = random.randint(0, 100)
    return "".join(random.choices(string.printable, k=length))

def rand_bytes():
    return bytes(rand_str(), "utf-8", errors="ignore")

def rand_list(depth=0):
    if depth > 2:
        return []
    return [rand_value(depth+1) for _ in range(random.randint(0,5))]

def rand_dict(depth=0):
    if depth > 2:
        return {}
    return {rand_str(): rand_value(depth+1) for _ in range(random.randint(0,5))}

POOL = [None, True, False, rand_int, rand_float, rand_str, rand_bytes, rand_list, rand_dict]

def rand_value(depth=0):
    v = random.choice(POOL)
    if callable(v):
        return v() if v in (rand_int, rand_float, rand_str, rand_bytes) else v(depth)
    return v

def gen_arg_for_param(param):
    ann = param.annotation
    if ann is inspect._empty:
        return rand_value()
    try:
        if ann is int:
            return rand_int()
        if ann is float:
            return rand_float()
        if ann is str:
            return rand_str()
        if ann is bytes:
            return rand_bytes()
        if ann is list:
            return rand_list()
        if ann is dict:
            return rand_dict()
    except Exception:
        pass
    return rand_value()

def discover_functions(root):
    sys.path.insert(0, root)
    found = []
    artifacts_dir = os.path.abspath(os.path.join(root, "artifacts"))
    skip_files = {
        os.path.abspath(__file__),
        # os.path.abspath(os.path.join(root, "forensics.py")),  # no longer skip forensics.py
    }
    for dirpath, dirnames, filenames in os.walk(root):
        # skip artifacts dir entirely
        if os.path.abspath(dirpath).startswith(artifacts_dir):
            continue
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            path = os.path.abspath(os.path.join(dirpath, fname))
            if path in skip_files:
                continue
            rel = os.path.relpath(path, root)
            # skip hidden/underscore modules
            if os.path.basename(rel).startswith("_"):
                continue
            # Load module by file location to avoid package-import quirks
            mod_name = rel[:-3].replace(os.sep, ".")  # used for a nicer name
            loader_name = mod_name.replace(".", "_")
            try:
                spec = importlib.util.spec_from_file_location(loader_name, path)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                sys.modules[loader_name] = module
                spec.loader.exec_module(module)
            except Exception:
                continue
            for _, obj in inspect.getmembers(module, inspect.isfunction):
                if inspect.getmodule(obj) is module:
                    found.append((module, obj))
    return found

def instrument_and_choose(functions, max_funcs=5):
    chosen = []
    for mod, fn in functions:
        if len(chosen) >= max_funcs:
            break
        wrapped = forensic_wrap(fn)
        setattr(mod, fn.__name__, wrapped)
        chosen.append((mod, wrapped))
    return chosen

def fuzz_function(module, fn, trials=50):
    sig = inspect.signature(fn)
    params = list(sig.parameters.values())
    bugs = []
    for t in range(trials):
        args = []
        kwargs = {}
        for p in params:
            if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                if random.random() < 0.3:
                    if p.kind == inspect.Parameter.VAR_POSITIONAL:
                        args.extend([rand_value() for _ in range(random.randint(0,3))])
                    else:
                        kwargs.update({rand_str(): rand_value() for _ in range(random.randint(0,3))})
                continue
            if p.default is not inspect._empty and random.random() < 0.5:
                continue
            val = gen_arg_for_param(p)
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
                args.append(val)
            else:
                kwargs[p.name] = val
        try:
            fn(*args, **kwargs)
        except Exception as e:
            tb = traceback.format_exc()
            report = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "module": module.__name__,
                "function": fn.__name__,
                "args": repr(args),
                "kwargs": repr(kwargs),
                "exception": type(e).__name__,
                "traceback": tb
            }
            fname = f"{module.__name__}__{fn.__name__}__{int(datetime.utcnow().timestamp())}_{t}.json"
            path = os.path.join(REPORT_DIR, fname)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            bugs.append(path)
    return bugs

def main():
    functions = discover_functions(PROJECT_ROOT)
    if not functions:
        print("No functions discovered to fuzz.")
        return 0
    chosen = instrument_and_choose(functions, max_funcs=5)
    all_bugs = []
    for mod, fn in chosen:
        print(f"Fuzzing {mod.__name__}.{fn.__name__} ...")
        bugs = fuzz_function(mod, fn, trials=60)
        all_bugs.extend(bugs)
    if all_bugs:
        print(f"Found {len(all_bugs)} failing cases. Reports in {REPORT_DIR}")
        for b in all_bugs[:10]:
            print(" -", b)
        return 1
    print("No crashes found by fuzz.py")
    return 0

if __name__ == "__main__":
    sys.exit(main())