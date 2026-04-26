"""
WebGuard AI — Celery Task Queue
Async task processing for long-running scans.
"""
from core.config import settings

class DummyCelery:
    def __init__(self, *args, **kwargs):
        self.conf = DummyConf()
    def task(self, *args, **kwargs):
        def decorator(f):
            return f
        return decorator

class DummyConf:
    def update(self, *args, **kwargs):
        pass

celery_app = DummyCelery("webguard")

