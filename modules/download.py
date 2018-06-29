import requests
import sys

def stix(endpoint):
    """Get STIX data from https://attackgui.mitre.org."""
    endpoints = ['attack-patterns', 'course-of-actions', 'identities', 'intrusion-sets', 'malwares', 'relationships', 'tools']

    res = None
    if endpoint in endpoints:
        try:
            res = requests.get('https://attackgui.mitre.org/api/{0}'
                               .format(endpoint), verify=False)
        except requests.exceptions.RequestException as ex:
            raise RequestException("""Error connecting to
            https://attackgui.mitre.org/api/{0}""".format(endpoint))
    else:
        raise ValueError("""https://attackgui.mitre.org/api/{0} is not
        a valid API endpoint""".format(endpoint))
        sys.exit(1)

    return res.json()['data']