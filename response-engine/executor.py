from notifier import send_notification,send_approval_email,send_combined_action_email

class ResponseExecutor:
    def __init__(self):
        pass

    def execute(self,actions):
        results=[]
        if not actions:
            return results

        velociraptor_actions=[a for a in actions if a.get("tool","").lower()=="velociraptor"]
        notification_actions=[a for a in actions if a.get("tool","").lower()=="notification"]
        other_actions=[a for a in actions if a.get("tool","").lower() not in ("velociraptor","notification")]

        if velociraptor_actions and notification_actions:
            try:
                combined_results=send_combined_action_email(
                    velociraptor_actions+notification_actions
                )
            except Exception as e:
                combined_results=[
                    {"success":False,"message":str(e)}
                    for _ in (velociraptor_actions+notification_actions)
                ]
            results.extend(combined_results)

        elif velociraptor_actions:
            for action in velociraptor_actions:
                try:
                    result=send_approval_email(action)
                except Exception as e:
                    result={
                        "success":False,
                        "tool":"velociraptor",
                        "message":str(e)
                    }
                results.append(result)

        elif notification_actions:
            for action in notification_actions:
                try:
                    result=send_notification(action)
                except Exception as e:
                    result={
                        "success":False,
                        "tool":"notification",
                        "message":str(e)
                    }
                results.append(result)

        for action in other_actions:
            tool=action.get("tool","").lower()

            try:
                if tool=="log":
                    result={
                        "success":True,
                        "tool":"log",
                        "action":action.get("action"),
                        "message":"Incident logged."
                    }
                elif tool=="iris":
                    result={
                        "success":False,
                        "tool":"iris",
                        "message":"IRIS connector not implemented."
                    }
                else:
                    result={
                        "success":False,
                        "tool":tool,
                        "message":f"Unsupported tool '{tool}'."
                    }
            except Exception as e:
                result={
                    "success":False,
                    "tool":tool,
                    "message":str(e)
                }

            results.append(result)

        return results

executor=ResponseExecutor()

def execute_actions(actions):
    return executor.execute(actions)