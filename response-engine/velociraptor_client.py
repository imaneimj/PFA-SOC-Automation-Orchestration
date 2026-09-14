import grpc
import json
import pyvelociraptor

from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

import time
class VelociraptorClient:

    def __init__(self):

        config = pyvelociraptor.LoadConfigFile("api_client.yaml")

        creds = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode("utf8"),
            private_key=config["client_private_key"].encode("utf8"),
            certificate_chain=config["client_cert"].encode("utf8")
        )

        options = (
            (
                "grpc.ssl_target_name_override",
                "VelociraptorServer",
            ),
        )

        self.channel = grpc.secure_channel(
            config["api_connection_string"],
            creds,
            options
        )

        self.stub = api_pb2_grpc.APIStub(self.channel)

        print("[+] Connected to Velociraptor API")


    def execute_vql(self, query):

        request = api_pb2.VQLCollectorArgs(
            max_wait=1,
            max_row=100,
            Query=[
                api_pb2.VQLRequest(
                    Name="DecisionEngine",
                    VQL=query
                )
            ]
        )

        results = []

        for response in self.stub.Query(request):
            if response.Response:
                results.extend(json.loads(response.Response))

        return results
    

    def get_clients(self):

        query = """
        SELECT
            client_id,
            os_info.hostname AS hostname,
            os_info.system AS os
        FROM clients()
        """

        return self.execute_vql(query)


    def get_client_by_hostname(self, hostname):

        query = f"""
        SELECT
            client_id,
            os_info.hostname AS hostname,
            os_info.system AS os
        FROM clients()
        WHERE os_info.hostname = "{hostname}"
        """

        results = self.execute_vql(query)

        if results:
            return results[0]

        return None
   
    def collect_artifact(self, client_id, artifact, parameters=None):

        if parameters is None:
            parameters = {}

        env_string = ""

        if parameters:

            params = []

            for key, value in parameters.items():

                value = str(value).replace("\\", "\\\\")
                value = value.replace('"', '\\"')

                params.append(
                    f'{key}="{value}"'
                )

            env_string = (
                ", env=dict("
                + ",".join(params)
                + ")"
            )

        else:

            env_string = ", env=dict()"
        query = f"""
        SELECT
            collect_client(
                client_id="{client_id}",
                artifacts="{artifact}"
                {env_string}
            ).flow_id AS flow_id
        FROM scope()
        """

        print("=" * 80)
        print("VELOCIRAPTOR COLLECTION")
        print("CLIENT ID :", client_id)
        print("ARTIFACT  :", artifact)
        print("PARAMETERS:", parameters)
        print("VQL:")
        print(query)
        print("=" * 80)

        try:

            result = self.execute_vql(query)

        except Exception as e:

            print("=" * 80)
            print("VQL ERROR")
            print(str(e))
            print("=" * 80)

            return {
                "success": False,
                "error": str(e)
            }
        print("=" * 80)
        print("RAW RESULT FROM VELOCIRAPTOR")
        print(json.dumps(result, indent=2, default=str))
        print("=" * 80)

        if not result:

            return {
                "success": False,
                "error": "Velociraptor returned no result."
            }
        flow_id = result[0].get("flow_id")

        print("=" * 80)
        print("FLOW ID :", flow_id)
        print("=" * 80)

        if not flow_id:

            return {
                "success": False,
                "error": "Velociraptor did not return a flow ID.",
                "raw_result": result
            }

        print("=" * 80)
        print("ARTIFACT SUCCESSFULLY SCHEDULED")
        print("ARTIFACT :", artifact)
        print("CLIENT ID:", client_id)
        print("FLOW ID  :", flow_id)
        print("=" * 80)

        return {
            "success": True,
            "flow_id": flow_id,
            "status": "STARTED",
            "artifact": artifact,
            "client_id": client_id
        }

 
    def wait_flow(self, client_id, flow_id):

        while True:

            query = f"""
            SELECT
                session_id,
                state
            FROM flows(
                client_id="{client_id}"
            )
            WHERE session_id="{flow_id}"
            """

            result = self.execute_vql(query)


            if result:

                state = result[0]["state"]

                print(flow_id, state)


                if state == "FINISHED":
                    return


            time.sleep(2)
    def get_flow_results(self, client_id, flow_id):

        query = f"""
        SELECT *
        FROM flow_results(
            client_id="{client_id}",
            flow_id="{flow_id}"
        )
        """

        return self.execute_vql(query)