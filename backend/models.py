from datetime import datetime

from mongoengine import DateTimeField, DictField, Document, IntField, ListField, StringField


class TaskRun(Document):
    task_id = StringField(required=True)
    target = StringField()
    started_at = DateTimeField(default=datetime.now)
    finished_at = DateTimeField()
    status = StringField(default="running")  # queued | running | paused | success | failed | stopped | unknown
    exit_code = IntField()
    triggered_by = StringField(default="manual")
    pid = IntField()
    log_path = StringField()
    tool = StringField()
    scope_kind = StringField()  # all | programs | domains
    scope = ListField(StringField())
    max_minutes = IntField()
    source = StringField(default="dashboard")  # dashboard | systemd | heavy-lane | pipeline
    group_id = StringField()
    summary = DictField()

    meta = {
        "indexes": [
            {"fields": ["task_id", "-started_at"]},
            {"fields": ["status"]},
            {"fields": ["group_id"]},
        ]
    }
