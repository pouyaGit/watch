import os

from fastapi.templating import Jinja2Templates

from backend.tasks_registry import PROJECT_ROOT

TEMPLATES_DIR = os.path.join(PROJECT_ROOT, "web", "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)
