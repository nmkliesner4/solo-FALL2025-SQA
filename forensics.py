import os
import json
import traceback
from datetime import datetime
from functools import wraps

LOG_DIR = os.path.join(os.path.dirname(__file__), "artifacts", "forensics")
os.makedirs(LOG_DIR, exist_ok=True)

def forensic_wrap(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "function": f"{func.__module__}.{func.__name__}",
            "args_repr": repr(args),
            "kwargs_repr": repr(kwargs),
            "stack": traceback.format_stack()
        }
        log_name = f"{func.__module__}__{func.__name__}__{int(datetime.utcnow().timestamp()*1000)}.json"
        path = os.path.join(LOG_DIR, log_name)
        try:
            result = func(*args, **kwargs)
            entry["result_repr"] = repr(result)
            entry["status"] = "ok"
            return result
        except Exception as e:
            entry["exception"] = {"type": type(e).__name__, "message": str(e), "traceback": traceback.format_exc()}
            entry["status"] = "exception"
            raise
        finally:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(entry, f, indent=2)
            except Exception:
                pass
    return wrapper