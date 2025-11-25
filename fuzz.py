#!/usr/bin/env python3
"""
Lightweight fuzz harness that:
- Finds Python functions and class methods under MLForensics/
- Picks up to 5 targets at random
- Calls each target repeatedly with randomly generated inputs
- Logs exceptions to fuzz_results.log

Usage:
    python fuzz.py [--dir PATH_TO_MLForensics] [--iterations N] [--timeout SEC] [--seed N]
"""
import argparse
import ast
import importlib.util
import inspect
import os
import random
import string
import sys
import traceback
from multiprocessing import Process, Queue
from types import MethodType

try:
    import numpy as np  # optional
except Exception:
    np = None

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def find_python_targets(root_dir):
    targets = []  # list of tuples (file_path, qualname)
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    src = f.read()
                tree = ast.parse(src, fp)
            except Exception:
                continue
            for node in ast.walk(tree):
                # top-level functions
                if isinstance(node, ast.FunctionDef):
                    # ensure it's top-level (not nested inside another function)
                    if isinstance(getattr(node, "parent", None), ast.Module) or not hasattr(node, "parent"):
                        # compute qualname by walking parents
                        qual = node.name
                        parent = getattr(node, "parent", None)
                        # walk up to see if inside a class
                        p = node
                        qparts = []
                        while hasattr(p, "parent") and p.parent is not None:
                            p = p.parent
                            if isinstance(p, ast.ClassDef):
                                qparts.insert(0, p.name)
                        if qparts:
                            qual = ".".join(qparts + [node.name])
                        targets.append((fp, qual))
                # class methods (we capture by scanning classdefs methods as above)
            # annotate parents for nested detection
            # (we set parents after initial walk to avoid double reads)
            # actually do second pass
            # build AST parents
            tree = ast.parse(src, fp)
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    setattr(child, "parent", parent)
            # collect functions again but using parent info
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # find enclosing class chain
                    qparts = []
                    p = node
                    while hasattr(p, "parent") and p.parent is not None:
                        p = p.parent
                        if isinstance(p, ast.ClassDef):
                            qparts.insert(0, p.name)
                    qual = ".".join(qparts + [node.name]) if qparts else node.name
                    targets.append((fp, qual))
    # dedupe
    seen = set()
    dedup = []
    for f, q in targets:
        k = (os.path.normpath(f), q)
        if k not in seen:
            seen.add(k)
            dedup.append((f, q))
    return dedup


def import_module_from_path(path):
    name = "fuzz_mod_" + str(abs(hash(os.path.abspath(path))))  # unique-ish
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None:
        raise ImportError(path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    loader = spec.loader
    if loader is None:
        raise ImportError(path)
    loader.exec_module(mod)
    return mod


def generate_value_for_param(name, ann):
    # basic heuristics by annotation or name
    if ann is not None:
        try:
            ann_str = str(ann)
        except Exception:
            ann_str = ""
    else:
        ann_str = ""
    lname = name.lower()
    # explicit annotation hints
    if "int" in ann_str:
        return random.randint(-1000, 1000)
    if "float" in ann_str:
        return random.uniform(-1e6, 1e6)
    if "bool" in ann_str:
        return random.choice([True, False])
    if "str" in ann_str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(0, 40)))
    if "bytes" in ann_str:
        return bytes(random.getrandbits(8) for _ in range(random.randint(0, 40)))
    if "list" in ann_str or "sequence" in ann_str or lname.endswith("s"):
        # list of random simple elements
        return [generate_value_for_param(name + "_item", None) for _ in range(random.randint(0, 5))]
    if "dict" in ann_str or "mapping" in ann_str:
        return {str(i): generate_value_for_param(name + "_v", None) for i in range(random.randint(0, 4))}
    # name-based heuristics
    if "path" in lname or "file" in lname:
        return ""  # empty path
    if "image" in lname or "array" in lname or "tensor" in lname:
        if np is not None:
            return np.random.randn(random.randint(1, 4), random.randint(1, 4))
    if "n" == lname or lname.endswith("_n") or lname.startswith("n_"):
        return random.randint(0, 20)
    # fallback: random small variety
    choices = [
        lambda: None,
        lambda: random.randint(-100, 100),
        lambda: random.uniform(-1e3, 1e3),
        lambda: "".join(random.choices(string.ascii_letters, k=random.randint(0, 20))),
        lambda: [random.randint(0, 10) for _ in range(random.randint(0, 5))],
        lambda: {str(i): i for i in range(random.randint(0, 3))}
    ]
    return random.choice(choices)()


def build_args_for_callable(obj, parent_class=None):
    sig = None
    try:
        sig = inspect.signature(obj)
    except Exception:
        return (), {}
    args = []
    kwargs = {}
    params = list(sig.parameters.values())
    for p in params:
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            # provide some generic content
            if p.kind == p.VAR_POSITIONAL:
                args.extend([])
            continue
        if p.name in ("self", "cls"):
            # skip binding here; handled by binding to instance
            continue
        ann = None
        if p.annotation is not inspect._empty:
            ann = p.annotation
        val = generate_value_for_param(p.name, ann)
        if p.kind == p.POSITIONAL_ONLY or p.kind == p.POSITIONAL_OR_KEYWORD:
            args.append(val)
        else:
            kwargs[p.name] = val
    return tuple(args), kwargs


def safe_invoke(target_callable, args, kwargs, timeout):
    """
    Run target_callable(*args, **kwargs) in a separate process and capture exceptions/results.
    Returns tuple (ok, result_or_trace)
    """
    q = Queue()

    def runner(q, args, kwargs):
        try:
            res = target_callable(*args, **kwargs)
            q.put(("ok", repr(res)))
        except Exception:
            q.put(("err", traceback.format_exc()))

    p = Process(target=runner, args=(q, args, kwargs))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        return False, "timeout"
    if not q.empty():
        status, payload = q.get()
        if status == "ok":
            return True, payload
        else:
            return False, payload
    return True, "no-output"


def instantiate_class_safe(cls):
    try:
        return cls()
    except Exception:
        try:
            inst = object.__new__(cls)
            return inst
        except Exception:
            return None


def fuzz_targets(targets, iterations=100, timeout=2, seed=None, log_path=None):
    if seed is not None:
        random.seed(seed)
    if not targets:
        print("No targets found.")
        return
    chosen = random.sample(targets, min(5, len(targets)))
    log_lines = []
    for i, (fp, qual) in enumerate(chosen, 1):
        label = f"{os.path.relpath(fp, PROJECT_ROOT)}::{qual}"
        print(f"[{i}/{len(chosen)}] Fuzzing {label}")
        try:
            mod = import_module_from_path(fp)
        except Exception as e:
            log_lines.append(f"Failed to import {fp}: {e}\n{traceback.format_exc()}\n")
            continue
        # get attribute
        parts = qual.split(".")
        obj = mod
        parent_obj = None
        try:
            for p in parts:
                parent_obj = obj
                obj = getattr(obj, p)
        except Exception as e:
            log_lines.append(f"Failed to resolve {label}: {e}\n{traceback.format_exc()}\n")
            continue
        # handle method binding if parent is a class
        bound_callable = obj
        if inspect.isfunction(obj) and isinstance(parent_obj, type):
            # instantiate parent and bind
            inst = instantiate_class_safe(parent_obj)
            if inst is not None:
                bound_callable = MethodType(obj, inst)
            else:
                # try calling unbound with first arg as None
                bound_callable = obj
        # run iterations
        for it in range(iterations):
            args, kwargs = build_args_for_callable(bound_callable)
            ok, result = safe_invoke(bound_callable, args, kwargs, timeout)
            if not ok:
                log_lines.append(f"Target:{label} Iter:{it} args={args} kwargs={kwargs}\nException:\n{result}\n\n")
    # write log
    log_path = log_path or os.path.join(PROJECT_ROOT, "fuzz_results.log")
    with open(log_path, "a", encoding="utf-8") as lf:
        lf.write("\n".join(log_lines))
    print(f"Fuzzing complete. Logged {len(log_lines)} events to {log_path}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dir", default=os.path.join(PROJECT_ROOT, "MLForensics"), help="Path to MLForensics dir")
    p.add_argument("--iterations", "-n", type=int, default=100, help="Iterations per target")
    p.add_argument("--timeout", type=float, default=2.0, help="Seconds per call before killing")
    p.add_argument("--seed", type=int, default=None, help="Random seed")
    p.add_argument("--list", action="store_true", help="List discovered targets and exit")
    args = p.parse_args()
    root = os.path.abspath(args.dir)
    if not os.path.isdir(root):
        print(f"Directory not found: {root}")
        sys.exit(1)
    targets = find_python_targets(root)
    if args.list:
        for t in targets:
            print(f"{os.path.relpath(t[0], PROJECT_ROOT)} :: {t[1]}")
        return
    fuzz_targets(targets, iterations=args.iterations, timeout=args.timeout, seed=args.seed)


if __name__ == "__main__":
    main()