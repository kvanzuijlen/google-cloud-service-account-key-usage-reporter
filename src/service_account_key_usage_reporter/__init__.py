import csv
import dataclasses
import os
import typing
from pathlib import Path

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from service_account_key_usage_reporter.model import ServiceAccountKeyInfo


def _folders(service, parent) -> typing.Dict:
    return service.folders().list(parent=parent).execute()


def _projects(service, parent) -> typing.Dict:
    return service.projects().list(parent=parent).execute()


def _get_all_child_projects(service, parent) -> typing.Generator[tuple[str, str], None, None]:
    if all_folders := _folders(parent=parent, service=service):
        for folder in all_folders.get("folders", []):
            yield from _get_all_child_projects(service=service, parent=folder["name"])
    for project in _projects(parent=parent, service=service).get("projects", []):
        yield project["name"], project["displayName"]


def get_service_account_key_usage(toplevel_parent: str) -> typing.Generator[ServiceAccountKeyInfo, None, None]:
    with build('cloudresourcemanager', 'v3') as service:
        all_projects = _get_all_child_projects(service=service, parent=toplevel_parent)
        with build('policyanalyzer', 'v1') as analyzer:
            for project_id, project_name in all_projects:
                activities = analyzer.projects().locations().activityTypes().activities().query(parent=f"{project_id}/locations/global/activityTypes/serviceAccountKeyLastAuthentication")
                try:
                    response = activities.execute()
                except HttpError as exception:
                    if exception.reason.startswith("Policy Analyzer API has not been used in project"):
                        print(f"Policy Analyzer API has not been used in project {project_name}")
                        yield ServiceAccountKeyInfo(
                            project_id=project_id,
                            project_name=project_name,
                        )
                        continue
                    raise exception
                for activity in response.get("activities", []):
                    yield ServiceAccountKeyInfo(
                        project_id=project_id,
                        project_name=project_name,
                        full_resource_name=activity["fullResourceName"],
                        last_authenticated_time=activity.get("activity", {}).get("lastAuthenticatedTime"),
                        observation_start=activity.get("observationPeriod", {})["startTime"],
                        observation_end=activity.get("observationPeriod", {})["endTime"],
                    )


if __name__ == "__main__":
    with Path("./service_account_key_usage_report.csv").open(mode="w") as file:
        writer = csv.DictWriter(f=file, fieldnames=["project_id", "project_name", "full_resource_name", "last_authenticated_time", "observation_start", "observation_end", "error"])
        writer.writeheader()
        for data in get_service_account_key_usage(toplevel_parent=os.getenv("TOPLEVEL_PARENT")):
            data_dict = dataclasses.asdict(data)
            data_dict["error"] = None
            if data.full_resource_name is None:
                data_dict["error"] = f"Policy Analyzer API has not been used in project {data.project_name}"
            writer.writerow(data_dict)
