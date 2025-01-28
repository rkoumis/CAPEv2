from typing import List, Optional

from pydantic import BaseModel, Field


class Summary(BaseModel):
    vt_file_summary: Optional[str] = Field(validation_alias="target.file.virustotal.summary")
    vt_url_summary: Optional[str] = Field(validation_alias="url.virustotal.summary")
    malscore: Optional[float]
    detections: Optional[List[str]]
    pcap_sha256: Optional[str] = Field(validation_alias="network.pcap_sha256")
    mlist_cnt: Optional[int]
    f_mlist_cnt: Optional[int]
    clamav: Optional[List[str]] = Field(validation_alias="target.file.clamav")
    suri_tls_cnt: Optional[int]
    suri_alert_cnt: Optional[int]
    suri_http_cnt: Optional[int]
    suri_file_cnt: Optional[int]
    trid: Optional[int]


class Info(BaseModel):
    ...


class AnalysisConfigs(BaseModel):
    ...
