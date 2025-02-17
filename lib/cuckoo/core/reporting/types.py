from enum import Enum

# In Py3.11, this can be changed to StrEnum
class SearchCategories(Enum):
    FILE = "file"
    URL = "url"
    PCAP = "pcap"
    STATIC = "static"
