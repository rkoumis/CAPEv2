import abc
import datetime
from typing import List, Optional

from pydantic import BaseModel as PydanticBaseModel
from pydantic import Extra


class BaseModel(PydanticBaseModel, abc.ABC):
    class Config:
        allow_population_by_field_name = True
        extra = Extra.allow


class Machine(BaseModel):
    id: Optional[int]
    status: Optional[str]
    name: Optional[str]
    label: Optional[str]
    platform: Optional[str]
    manager: Optional[str]
    started_on: Optional[datetime.datetime]
    shutdown_on: Optional[datetime.datetime]


class Info(BaseModel):
    id: Optional[int]
    version: Optional[str]
    started: Optional[datetime.datetime]
    ended: Optional[datetime.datetime]
    duration: Optional[int]
    category: Optional[str]
    machine: Optional[Machine]
    package: Optional[str]
    timeout: Optional[bool]
    tlp: Optional[str]
    user_id: Optional[int]


class Summary(BaseModel):
    info: Optional[Info]
    vt_file_summary: Optional[str]
    vt_url_summary: Optional[str]
    malscore: Optional[float]
    detections: Optional[List[dict]]
    pcap_sha256: Optional[str]
    mlist_cnt: Optional[int]
    f_mlist_cnt: Optional[int]
    clamav: Optional[List[str]]
    suri_tls_cnt: Optional[int]
    suri_alert_cnt: Optional[int]
    suri_http_cnt: Optional[int]
    suri_file_cnt: Optional[int]
    trid: Optional[int]


class AnalysisConfigs(BaseModel):
    ...
