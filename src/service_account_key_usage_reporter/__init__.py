import csv
import os
from pathlib import Path

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


def _folders(service, parent):
    return service.folders().list(parent=parent).execute()


def _projects(service, parent):
    return service.projects().list(parent=parent).execute()


def _get_all_child_projects(service, parent):
    if all_folders := _folders(parent=parent, service=service):
        for folder in all_folders.get("folders", []):
            yield from _get_all_child_projects(service=service, parent=folder["name"])
    for project in _projects(parent=parent, service=service).get("projects", []):
        yield project["name"], project["displayName"]


def get_service_account_key_usage(toplevel_parent: str):
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
                        yield {
                            "project": project_name,
                            "fullResourceName": None,
                            "lastAuthenticatedTime": None,
                            "observation_start": None,
                            "observation_end": None,
                            "error": f"Policy Analyzer API has not been used in project {project_name}",
                        }
                        continue
                    raise exception
                for activity in response.get("activities", []):
                    yield {
                        "project": project_name,
                        "fullResourceName": activity["fullResourceName"],
                        "lastAuthenticatedTime": activity.get("activity", {}).get("lastAuthenticatedTime"),
                        "observation_start": activity.get("observationPeriod", {})["startTime"],
                        "observation_end": activity.get("observationPeriod", {})["endTime"],
                        "error": None,
                    }


if __name__ == "__main__":
    with Path("./service_account_key_usage_report.csv").open(mode="w") as file:
        writer = csv.DictWriter(f=file, fieldnames=["project", "fullResourceName", "lastAuthenticatedTime", "observation_start", "observation_end", "error"])
        writer.writeheader()
        for data in get_service_account_key_usage(toplevel_parent=os.getenv("TOPLEVEL_PARENT")):
            writer.writerow(data)
