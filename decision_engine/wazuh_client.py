import requests
import urllib3
urllib3.disable_warnings()
WAZUH_API = "https://172.18.70.51:55000"
USERNAME = "wazuh-wui"
PASSWORD = "MyS3cr37P450r.*-"
def get_token():
    url = f"{WAZUH_API}/security/user/authenticate"
    response = requests.post(
        url,
        auth=(USERNAME, PASSWORD),
        verify=False
    )
    response.raise_for_status()
    return response.json()["data"]["token"]
def get_agent(agent_id):
    try:
        token = get_token()
        headers = {
            "Authorization": f"Bearer {token}"
        }
        url = f"{WAZUH_API}/agents"
        params = {
            "agents_list": agent_id
        }
        response = requests.get(
            url,
            headers=headers,
            params=params,
            verify=False
        )
        response.raise_for_status()
        data = response.json()
        agents = data["data"]["affected_items"]
        if len(agents) > 0:
            return agents[0]
        return {}
    except Exception as e:
        print(
            "[WAZUH CLIENT ERROR]",
            e)
        return {}