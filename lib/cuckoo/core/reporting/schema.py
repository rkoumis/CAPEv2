from __future__ import annotations
import abc
import datetime
from typing import Any, List

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, Field


class BaseModel(PydanticBaseModel, abc.ABC):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class Machine(BaseModel):
    id: int | None = None
    status: str | None = None
    name: str | None = None
    label: str | None = None
    platform: str | None = None
    manager: str | None = None
    started_on: datetime.datetime | None = None
    shutdown_on: datetime.datetime | None = None


class Info(BaseModel):
    id: int | None = None
    version: str | None = None
    started: datetime.datetime | None = None
    ended: datetime.datetime | None = None
    duration: int | None = None
    category: str | None = None
    machine: Machine | None = None
    package: str | None = None
    timeout: bool | None = None
    tlp: str | None = None
    user_id: int | None = None


class Summary(BaseModel):
    info: Info | None = None
    vt_file_summary: str | None = None
    vt_url_summary: str | None = None
    malscore: float | None = None
    detections: List[dict] | None = None
    pcap_sha256: str | None = None
    mlist_cnt: int | None = None
    f_mlist_cnt: int | None = None
    clamav: List[str] | None = None
    suri_tls_cnt: int | None = None
    suri_alert_cnt: int | None = None
    suri_http_cnt: int | None = None
    suri_file_cnt: int | None = None
    trid: int | None = None


class Behavior(BaseModel):
    class ProcessCall(BaseModel):
        oid: str = Field(serialization_alias="$oid")

    class Process(BaseModel):
        process_id: int
        process_name: str | None = None
        parent_id: int | None = None
        module_path: str | None = None
        first_seen: datetime.datetime | None = None
        calls: list[Behavior.ProcessCall] | None = None
        threads: list[str] | None = None
        environ: dict[str, str] | None = None
        file_activities: dict[str, Any] | None = None

    info: Info | None = None
    detections2pid: dict | None = None
    processes: list[Behavior.Process] | None = None
    process_tree: list | None = None


class Domain(BaseModel):
    ip: str | None = None
    domain: str | None = None


class Network(BaseModel):
    info: Info | None = None
    network: dict | None = None
    domains: List[Domain] | None = None
    suricata: list | None = None
    pcapng: list | None = None


class CAPE(BaseModel):
    info: Info | None = None
    payloads: list | None = None
    configs: list | None = None


class AnalysisConfigs(BaseModel):
    ...
