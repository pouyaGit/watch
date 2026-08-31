"""
backend/models.py — mongoengine Documents for the Tasks subsystem.

These are the only NEW models added by the Watch Dashboard v2 refactor.
The existing models (Programs, Subdomains, LiveSubdomains, Http, Urls,
Endpoints, DnsBruteStatus) live in database/db.py and are untouched.

The connection is established in database/db.py via mongoengine.connect();
this module just declares Document subclasses on top of the same database.
"""
from datetime import datetime

from mongoengine import (
    DateTimeField,
    Document,
    IntField,
    StringField,
    BooleanField,
)


class TaskRun(Document):
    """One execution of a registered task.

    `task_id` is a stable key from backend/tasks_registry.py -- NOT a user
    string. `triggered_by` distinguishes manual ("manual") launches from
    scheduler-driven ones ("schedule"); that field only matters once APScheduler
    is wired in (Phase 2). For Phase 1 every run is "manual".
    """
    task_id       = StringField(required=True)
    started_at    = DateTimeField(default=datetime.now)
    finished_at   = DateTimeField()
    status        = StringField(default="running")    # running | success | failed
    exit_code     = IntField()
    triggered_by  = StringField(default="manual")
    pid           = IntField()
    log_path      = StringField()

    meta = {
        'indexes': [
            {'fields': ['task_id', '-started_at']},
            {'fields': ['status']},
        ]
    }


class TaskSchedule(Document):
    """Persistent cron schedule for a registered task (Phase 2 surface).

    Defined now so the collection exists when APScheduler lands; no router
    or runner code reads/writes it yet in Phase 1.
    """
    task_id       = StringField(required=True, unique=True)
    cron          = StringField(required=True)
    enabled       = BooleanField(default=True)
    args          = StringField(default="")
    next_run      = DateTimeField()
    last_run      = DateTimeField()

    meta = {
        'indexes': [
            {'fields': ['task_id'], 'unique': True},
        ]
    }