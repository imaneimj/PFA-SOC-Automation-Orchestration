import grpc
import json
import pyvelociraptor
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc
import time
class VelociraptorClient:
    def __init__(self):
        config=pyvelociraptor.LoadConfigFile("api_client.yaml")
        creds=grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode("utf8"),
            private_key=config["client_private_key"].encode("utf8"),
            certificate_chain=config["client_cert"].encode("utf8"))
        options=(("grpc.ssl_target_name_override","VelociraptorServer"),)
        self.channel=grpc.secure_channel(
            config["api_connection_string"],
            creds,
            options
        )
        self.stub=api_pb2_grpc.APIStub(self.channel)
        print("[+] Connected to Velociraptor API")
    def execute_vql(self,query):
        request=api_pb2.VQLCollectorArgs(
            max_wait=1,
            max_row=100,
            Query=[
                api_pb2.VQLRequest(
                    Name="DecisionEngine",
                    VQL=query
                )
            ]
        )
        results=[]
        for response in self.stub.Query(request):
            if response.Response:
                results.extend(json.loads(response.Response))
        return results

    def get_clients(self):
        query="""
        SELECT
            client_id,
            os_info.hostname AS hostname,
            os_info.system AS os
        FROM clients()
        """
        return self.execute_vql(query)

    def get_client_by_hostname(self,hostname):
        query=f"""
        SELECT
            client_id,
            os_info.hostname AS hostname,
            os_info.system AS os
        FROM clients()
        WHERE os_info.hostname = "{hostname}"
        """
        results=self.execute_vql(query)
        if results:
            return results[0]
        return None

    def collect_artifact(self,client_id,artifact,parameters=None):
        if parameters is None:
            parameters={}
        parameter_string=""
        if parameters:
            params=[]
            for key,value in parameters.items():
                if isinstance(value,bool):
                    value="Y" if value else "N"
                params.append(f'{key}="{value}"')
            parameter_string=", spec=dict("+",".join(params)+")"
        query=f"""
        SELECT
            collect_client(
                client_id="{client_id}",
                artifacts=["{artifact}"]
                {parameter_string}
            ) AS collection
        FROM scope()
        """
        result=self.execute_vql(query)
        if not result:
            return []
        collection=result[0].get("collection")
        if not isinstance(collection,dict):
            return []
        flow_id=collection.get("flow_id")
        if not flow_id:
            return []
        print(f"[+] Flow lancé : {flow_id}")
        while True:
            query=f"""
            SELECT session_id, state
            FROM flows(client_id="{client_id}")
            WHERE session_id="{flow_id}"
            """
            state=self.execute_vql(query)

            if state:
                status=state[0].get("state")
                print(f"{artifact} : {status}")

                if status=="FINISHED":
                    break

                if status in ("ERROR","FAILED","CANCELLED"):
                    return []

            time.sleep(2)

        return {
            "flow_id":flow_id,
            "results":self.get_flow_results(client_id,flow_id)
        }

    def wait_flow(self,client_id,flow_id):
        while True:
            query=f"""
            SELECT
                session_id,
                state
            FROM flows(
                client_id="{client_id}"
            )
            WHERE session_id="{flow_id}"
            """
            result=self.execute_vql(query)

            if result:
                state=result[0]["state"]
                print(flow_id,state)

                if state=="FINISHED":
                    return

            time.sleep(2)

    def get_flow_results(self,client_id,flow_id):
        query=f"""
        SELECT *
        FROM flow_results(
            client_id="{client_id}",
            flow_id="{flow_id}"
        )
        """
        return self.execute_vql(query)