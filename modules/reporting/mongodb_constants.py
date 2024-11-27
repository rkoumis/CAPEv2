"""Constants for MongoDB"""

# Collections:

ANALYSIS_COLL = "analysis"
CALLS_COLL = "calls"
CUCKOO_COLL = "cuckoo_schema"
FILES_COLL = "files"

FILE_KEY = "sha256"
FILE_REF_KEY = "file_ref"
ID_KEY = "_id"
INFO = "info"
INFO_ID_KEY = "info.id"
TARGET = "target"
TASK_IDS_KEY = "_task_ids"
VERSION = "version"

NORMALIZED_FILE_FIELDS = ("target.file", "dropped", "CAPE.payloads", "procdump", "procmemory")
