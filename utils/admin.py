import os
import shutil
import sys

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(".")), "..")
sys.path.append(CUCKOO_ROOT)


from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.core import reporting

repconf = Config("reporting")
reports: reporting.api.Reports = reporting.init_reports(repconf)


def remove(task_id):
    if not reports.delete(int(task_id)):
        return
    analyses_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))
    if path_exists(analyses_path):
        shutil.rmtree(analyses_path)


ids = sys.argv[1]
if "," in ids:
    ids = ids.split(",")
else:
    ids = [ids]
for id in ids:
    remove(id)
