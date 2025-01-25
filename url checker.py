import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
import json

url = str(input("Enter the URL e.g google.com:"))
# if API no longer valid make account on virustotal, click profile then API keys and copy your key and paste in between the quotes eg .Virustotal("yourapi")
with virustotal_python.Virustotal("c81f8100d1b0ccd6f72a0a43aa15916b7d1866b5c53f65298d9e931dc637a393") as vtotal:
    try:
        resp = vtotal.request("urls", data={"url": url}, method="POST")
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        report = vtotal.request(f"urls/{url_id}")
        pprint(report.object_type)
        pprint(report.data)
    except virustotal_python.VirustotalError as err:
        print(f"Failed to send URL: {url} for analysis and get the report: {err}")

with open(f"{url}_report.txt", 'w') as f:
    f.write(str(report.object_type) + "\n\n")
    json.dump(report.data, f, indent=4)

print(f"Report saved to {url}_report.txt")
