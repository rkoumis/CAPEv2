import abc
import datetime
from typing import Any, List

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, Field


class BaseModel(PydanticBaseModel, abc.ABC):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class Machine(BaseModel):
    id: int | None
    status: str | None
    name: str | None
    label: str | None
    platform: str | None
    manager: str | None
    started_on: datetime.datetime | None
    shutdown_on: datetime.datetime | None


class Info(BaseModel):
    id: int | None
    version: str | None
    started: datetime.datetime | None
    ended: datetime.datetime | None
    duration: int | None
    category: str | None
    machine: Machine | None
    package: str | None
    timeout: bool | None
    tlp: str | None
    user_id: int | None


class Summary(BaseModel):
    info: Info | None
    vt_file_summary: str | None
    vt_url_summary: str | None
    malscore: float | None
    detections: List[dict] | None
    pcap_sha256: str | None
    mlist_cnt: int | None
    f_mlist_cnt: int | None
    clamav: List[str] | None
    suri_tls_cnt: int | None
    suri_alert_cnt: int | None
    suri_http_cnt: int | None
    suri_file_cnt: int | None
    trid: int | None


class BehaviorProcessCall(BaseModel):
    oid: str = Field(serialization_alias="$oid")


class BehaviorProcess(BaseModel):
    process_id: int
    process_name: str | None
    parent_id: int | None
    module_path: str | None
    first_seen: datetime.datetime | None
    calls: list[BehaviorProcessCall] | None
    threads: list[str] | None
    environ: dict[str, str] | None
    file_activities: dict[str, Any] | None


class Behavior(BaseModel):
    info: Info | None
    detections2pid: dict | None
    processes: list[BehaviorProcess] | None
    process_tree: list | None


class Domain(BaseModel):
    ip: str | None
    domain: str | None


class Network(BaseModel):
    info: Info | None
    network: dict | None
    domains: List[Domain] | None
    suricata: list | None
    pcapng: list | None


class CAPE(BaseModel):
    info: Info | None
    payloads: list | None
    configs: list | None


class AnalysisConfigs(BaseModel):
    ...
