_store = {}
def save_report_html(incident_id, html):
    if incident_id and html:
        _store[str(incident_id)] = html

def get_report_html(incident_id):
    return _store.get(str(incident_id))

def pop_report_html(incident_id):
    return _store.pop(str(incident_id), None)