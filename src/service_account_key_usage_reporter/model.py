import dataclasses
import typing


@dataclasses.dataclass
class ServiceAccountKeyInfo:
    project_id: str
    project_name: str
    full_resource_name: typing.Optional[str] = None
    last_authenticated_time: typing.Optional[str] = None
    observation_start: typing.Optional[str] = None
    observation_end: typing.Optional[str] = None
