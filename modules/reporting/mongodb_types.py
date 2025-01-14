# Use mongoengine to store data in MongoDB.

import mongoengine

from modules.reporting.mongodb_constants import ANALYSIS_COLL, CALLS_COLL, CUCKOO_COLL, DB_ALIAS, FILES_COLL


class Analysis(mongoengine.DynamicDocument):
    meta = {"collection": ANALYSIS_COLL, "db_alias": DB_ALIAS, "allow_inheritance": False}


class Calls(mongoengine.DynamicDocument):
    meta = {"collection": CALLS_COLL, "db_alias": DB_ALIAS, "allow_inheritance": False}


class CuckooSchema(mongoengine.Document):
    meta = {"collection": CUCKOO_COLL, "db_alias": DB_ALIAS, "allow_inheritance": False}
    version = mongoengine.StringField(required=True, default=1)


class Files(mongoengine.DynamicDocument):
    meta = {"collection": FILES_COLL, "db_alias": DB_ALIAS, "allow_inheritance": False}
    id = mongoengine.StringField(primary_key=True)
