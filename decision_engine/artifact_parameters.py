from urllib.parse import urlparse
import os

def build_filefinder_parameters(normalized):
    syscheck = normalized.get("syscheck", {})
    ioc = normalized.get("ioc", {})

    if syscheck.get("path"):
        return {
            "SearchFilesGlob": syscheck["path"],
            "Calculate_Hash": True
        }
    urls = ioc.get("urls", [])
    if urls:
        filename = os.path.basename(urlparse(urls[0]).path)

        if filename:
            return {
                "SearchFilesGlob": f"/home/*/{filename}",
                "Calculate_Hash": True
            }
    if ioc.get("hashes"):
        return {
            "SearchFilesGlob": syscheck["path"],
            "Calculate_Hash": True
        }

    return None