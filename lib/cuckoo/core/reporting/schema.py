from __future__ import annotations
import abc
import datetime
from typing import Any

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, Field


class BaseModel(PydanticBaseModel, abc.ABC):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class Info(BaseModel):
    class Machine(BaseModel):
        id: int | None = None
        status: str | None = None
        name: str | None = None
        label: str | None = None
        platform: str | None = None
        manager: str | None = None
        started_on: datetime.datetime | None = None
        shutdown_on: datetime.datetime | None = None

    id: int | None = None
    version: str | None = None
    started: datetime.datetime | None = None
    ended: datetime.datetime | None = None
    duration: int | None = None
    category: str | None = None
    machine: Info.Machine | None = None
    package: str | None = None
    timeout: bool | None = None
    tlp: str | None = None
    user_id: int | None = None


class Summary(BaseModel):
    info: Info | None = None
    vt_file_summary: str | None = None
    vt_url_summary: str | None = None
    malscore: float | None = None
    detections: list[dict] = []
    pcap_sha256: str | None = None
    mlist_cnt: int | None = None
    f_mlist_cnt: int | None = None
    clamav: list[str] = []
    suri_tls_cnt: int | None = None
    suri_alert_cnt: int | None = None
    suri_http_cnt: int | None = None
    suri_file_cnt: int | None = None
    trid: int | None = None


class Behavior(BaseModel):
    class FileActivities(BaseModel):
        read_files: list[str] = []
        write_files: list[str] = []
        delete_files: list[str] = []

    class Process(BaseModel):
        process_id: int
        process_name: str | None = None
        parent_id: int | None = None
        module_path: str | None = None
        first_seen: datetime.datetime | None = None
        calls: list[Call] = []
        threads: list[str] = []  # would list[int] be better?
        environ: dict[str, str] | None = None
        file_activities: Behavior.FileActivities

    info: Info | None = None
    detections2pid: dict | None = None
    processes: list[Behavior.Process]
    process_tree: list = []


class Domain(BaseModel):
    ip: str | None = None
    domain: str | None = None


class Network(BaseModel):
    class Host(BaseModel):
        ip: str | None = None
        hostname: str | None = None
        country_name: str | None = None
        asn: str | None = None
        asn_name: str | None = None
        inaddrarpa: str | None = None

    class Domain(BaseModel):
        domain: str | None = None
        ip: str | None = None

    class Packet(BaseModel):
        src: str | None = None
        sport: int | None = None
        dst: str | None = None
        dport: int | None = None
        offset: int = 0
        time: float = 0.0

    class DNS(BaseModel):
        request: str
        type: str
        answers: list[Any] = []
        first_seen: datetime.datetime

    class HTTP(BaseModel):
        host: str | None = None
        data: str | None = None
        method: str | None = None
        user_agent: str = Field(alias="user-agent")

    pcap_sha256: str | None = None
    hosts: list[Network.Host] = []
    domains: list[Network.Domain] = []
    tcp: list[Network.Packet] = []
    udp: list[Network.Packet] = []
    icmp: list[Any] = []
    http: list[Network.HTTP] = []
    dns: list[Network.DNS] = []
    smtp: list[Any] = []
    irc: list[Any] = []
    dead_hosts: list[Any] = []
    http_ex: list[Any] = []
    https_ex: list[Any] = []
    smtp_ex: list[Any] = []


class CAPE(BaseModel):
    info: Info | None = None
    payloads: list = []
    configs: list = []


class Call(BaseModel):
    class Argument(BaseModel):
        name: str
        value: str
        pretty_value: str | None = None

    id: int
    timestamp: datetime.datetime | None = None
    thread_id: int | None = None
    caller: str | None = None
    parentcaller: str | None = None
    category: str | None = None
    api: str | None = None
    status: bool = False
    return_code: str | None = None
    arguments: list[Call.Argument] = []
    repeated: int = 0


class Calls(BaseModel):
    calls: list[Call] = []
    pid: int


class ProcMemory(BaseModel):
    class Chunk(BaseModel):
        # start, end and size are hexadecimal values
        start: str
        end: str
        size: str
        offset: int

    class MemoryMap(BaseModel):
        chunks: list[ProcMemory.Chunk] = []

    pid: int
    address_space: list[MemoryMap] = []


class AnalysisConfig(BaseModel):
    class HashGroup(BaseModel):
        md5: str
        sha1: str
        sha256: str
        sha512: str
        sha3_384: str

    associated_config_hashes: list[AnalysisConfig.HashGroup] = Field(alias="_associated_config_hashes", default_factory=list)
    associated_analysis_hashes: AnalysisConfig.HashGroup | None = Field(alias="_associated_analysis_hashes", default_factory=list)


class Suricata(BaseModel):
    class TLS(BaseModel):
        srcip: str
        srcport: int
        dstip: str
        dstport: int
        timestamp: datetime.datetime | None = None
        fingerprint: str | None = None
        issuerdn: str | None = None
        version: str | None = None
        subject: str | None = None
        sni: str | None = None
        serial: str | None = None
        notbefore: datetime.datetime | None = None
        notafter: datetime.datetime | None = None

    class DNS(BaseModel):
        class DNSQuery(BaseModel):
            type: str
            id: int
            rrname: str
            rrtype: str
            tx_id: int
            opcode: int

        timestamp: datetime.datetime | None = None
        flow_id: int
        pcap_cnt: int
        event_type: str
        src_ip: str
        src_port: int
        dest_ip: str
        dest_port: int
        proto: str | None = None
        dns: DNSQuery | None = None

    class Alert(BaseModel):
        sid: int
        gid: int
        rev: int | None = None
        severity: int
        srcip: str
        srcport: int
        dstip: str
        dstport: int
        protocol: str
        timestamp: datetime.datetime
        category: str | None = None
        signature: str

    alerts: list[Suricata.Alert] = []
    tls: list[Suricata.TLS] = []
    perf: list[str] = []
    files: list[str] = []
    http: list[str] = []
    dns: list[Suricata.DNS] = []
    ssh: list[str] = []
    fileinfo: list[str] = []
    eve_log_full_path: str | None = None
    alert_log_full_path: str | None = None
    tls_log_full_path: str | None = None
    http_log_full_path: str | None = None
    file_log_full_path: str | None = None
    ssh_log_full_path: str | None = None
    dns_log_full_path: str | None = None
