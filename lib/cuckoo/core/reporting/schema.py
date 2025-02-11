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
        answers: list[dict[str, str]] = []
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
    https_ex: list[dict[str, Any]] = []
    smtp_ex: list[Any] = []


class CAPE(BaseModel):
    class Payload(BaseModel):
        name: str
        path: str

    payloads: list[CAPE.Payload] = []
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
    files: list[dict[str, Any]] = []
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


class IOC(BaseModel):
    # WIP - more can be done here. But do we need it all?
    class ReducedInfo(BaseModel):
        # does not have "custom" (TODO enforce)
        class ReducedMachine(BaseModel):
            # does not have "id", "manager", or "label" (TODO enforce)
            status: str | None = None
            name: str | None = None
            platform: str | None = None
            started_on: datetime.datetime | None = None
            shutdown_on: datetime.datetime | None = None

        id: int | None = None
        version: str | None = None
        started: datetime.datetime | None = None
        ended: datetime.datetime | None = None
        duration: int | None = None
        category: str | None = None
        machine: IOC.ReducedInfo.ReducedMachine | None = None
        package: str | None = None
        timeout: bool | None = None
        tlp: str | None = None
        user_id: int | None = None

    class NetworkTraffic(BaseModel):
        tcp_count: int = 0
        udp_count: int = 0
        irc_count: int = 0
        http_count: int = 0
        dns_count: int = 0
        smtp_count: int = 0
        hosts_count: int = 0
        domains_count: int = 0
        http: list[Any] = []  # list of ?? str ?

    class IDS(BaseModel):
        class FileInfo(BaseModel):
            sha1: str
            sha256: str
            md5: str
            sha512: str

        totalalerts: int = 0
        totalfiles: int = 0
        alerts: list[Suricata.Alert] = []
        files: list[IOC.IDS.FileInfo] = []
        http: list[Any] = []  # list of ?? str ?

    class Network(BaseModel):
        traffic: IOC.NetworkTraffic
        hosts: list[Any] = []
        domains: list[Any] = []
        ids: IOC.IDS | None = None

    class PE(BaseModel):
        peid_signatures: list[Any] = []
        pe_timestamp: datetime.datetime | None = None
        pe_imphash: str | None = None
        pe_icon_hash: str | None = None
        pe_icon_fuzzy: str | None = None

    class PDF(BaseModel):
        objects: int = 0
        header: str | None = None
        pages: list[Any] = []  # ok?

    class Office(BaseModel):
        signatures: list[Any] = []  # ok?
        macros: list[Any] = []  # ok?

    class Files(BaseModel):
        modified: list[Any] = []  # ok?
        deleted: list[Any] = []  # ok?
        read: list[Any] = []  # ok?

    class Registry(BaseModel):
        modified: list[str] = []
        deleted: list[str] = []

    class ProcessTree(BaseModel):
        pid: int | None = None
        name: str | None = None
        spawned_processes: list[Any] = []  # TODO? It's a list of ProcessTree (recursion!)

    class Dropped(BaseModel):
        clamav: str | None = None
        sha256: str | None = None
        md5: str | None = None
        yara: str | None = None
        trid: str | None = None  # what _is_ a trid ?
        type: str | None = None
        guest_paths: list[str] | None = None  # list of str right?

    class Static(BaseModel):
        pe: IOC.PE | None = None
        pdf: IOC.PDF | None = None
        office: IOC.Office | None = None

    tr_extractor: str | None = None
    certs: list[Any] = []  # List of what?
    detections: list[Any] = []  # List of what?
    malscore: float = 0.0
    info: IOC.ReducedInfo | None = None
    # signatures - not populated
    target: dict[Any, Any] = {}  # how's this?
    network: IOC.Network | None = None
    static: IOC.Static | None = None
    files: IOC.Files | None = None
    registry: IOC.Registry | None = None
    mutexes: list[Any] | None = None  # how's this?
    executed_commands: list[str] | None = None  # how's this?
    process_tree: IOC.ProcessTree | None = None
    dropped: list[IOC.Dropped] | None = None  # how's this?


class DetailedIOC(IOC):
    class DetailedPE(IOC.PE):
        pe_versioninfo: str | None = None

    class DetailedNetwork(IOC.Network):
        class DetailedHTTP(BaseModel):
            host: str = ""
            data: str = ""
            method: str = ""
            ua: str = ""

        http: DetailedIOC.DetailedNetwork.DetailedHTTP | None = None

    class DetailedFiles(IOC.Files):
        read: list[Any] = []  # ok?

    class DetailedRegistry(IOC.Registry):
        read: list[Any] = []

    files: DetailedIOC.DetailedFiles | None = None
    registry: DetailedIOC.DetailedRegistry | None = None
    network: DetailedIOC.DetailedNetwork | None = None
    resolved_apis: list[str] = []
    strings: list[str] = []
    trid: list[str] = ["None matched"]


class File(BaseModel):
    pass


files: list[IOC.File] | None = None


class DroppedFile(BaseModel):
    name: str
    path: str
    # More fields to be added?
