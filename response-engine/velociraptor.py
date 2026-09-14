import config
from artifact_mapper import get_artifact
from velociraptor_client import VelociraptorClient

_LINUX_QUARANTINE_RESPONSES = {"AUTO", "QUARANTINE", "ISOLATE_NETWORK"}


def _inject_velociraptor_frontend_params(platform, response, parameters):

    if platform != "Linux" or response not in _LINUX_QUARANTINE_RESPONSES:
        return parameters

    parameters.setdefault(
        "VelociraptorServerIP",
        config.VELOCIRAPTOR_FRONTEND["ip"]
    )
    parameters.setdefault(
        "VelociraptorServerPort",
        config.VELOCIRAPTOR_FRONTEND["port"]
    )

    return parameters


def run_velociraptor_action(action: dict) -> dict:
    try:

        hostname = action.get("target")
        platform = action.get("platform")

        response = action.get("response") or action.get("artifact")

        parameters = action.get("parameters", {})

        if not hostname:
            raise ValueError("Missing target hostname.")

        if not platform:
            raise ValueError("Missing platform.")

        if not response:
            raise ValueError("Missing response/artifact type.")

        artifact = get_artifact(platform, response)

        parameters = _inject_velociraptor_frontend_params(
            platform, response, parameters
        )

        client = VelociraptorClient()

        endpoint = client.get_client_by_hostname(hostname)

        if endpoint is None:

            return {
                "success": False,
                "tool": "velociraptor",
                "hostname": hostname,
                "artifact": artifact,
                "message": f"Host '{hostname}' not found."
            }

        client_id = endpoint["client_id"]

        print(f"[+] Hostname : {hostname}")
        print(f"[+] Réponse demandée : {response}")
        print(f"[+] Client ID : {client_id}")
        print(f"[+] Artifact exécuté : {artifact}")
        if parameters:
            print(f"[+] Paramètres : {parameters}")

        collection = client.collect_artifact(
            client_id=client_id,
            artifact=artifact,
            parameters=parameters
        )

        if not collection or not collection.get("success"):

            error_message = (collection or {}).get(
                "error",
                "Flow did not complete successfully (ERROR/FAILED/CANCELLED ou timeout)."
            )

            print("=" * 80)
            print("VELOCIRAPTOR COLLECTION FAILED")
            print("ERROR :", error_message)
            print("=" * 80)

            return {
                "success": False,
                "tool": "velociraptor",
                "hostname": hostname,
                "client_id": client_id,
                "artifact": artifact,
                "message": error_message
            }

        flow_id = collection.get("flow_id")

        if not flow_id:

            return {
                "success": False,
                "tool": "velociraptor",
                "hostname": hostname,
                "client_id": client_id,
                "artifact": artifact,
                "message": "Velociraptor did not return a flow ID."
            }

        return {
            "success": True,
            "tool": "velociraptor",
            "hostname": hostname,
            "client_id": client_id,
            "response_type": response,
            "artifact": artifact,
            "flow_id": flow_id,
            "status": collection.get("status"),
            "message": "Artifact launched successfully."
        }

    except Exception as e:

        return {
            "success": False,
            "tool": "velociraptor",
            "message": str(e)
        }