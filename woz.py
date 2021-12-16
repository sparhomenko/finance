from datetime import datetime
from decimal import Decimal

from pytz import timezone
from requests import Session

from core import Account


class Property:
    def __init__(self, address):
        self.session = Session()
        self.api("")
        (doc,) = self.api("api/geocoder/v3/suggest", params={"query": address}).json()["docs"]
        address = self.api("api/geocoder/v3/lookup", params={"id": doc["id"]}).json()
        self.id = int(address["adresseerbaarobject_id"])

    def api(self, endpoint, **args):
        method = "POST" if "data" in args else "GET"
        response = self.session.request(method, f"https://www.wozwaardeloket.nl/{endpoint}", **args)
        if not 200 <= response.status_code < 300:
            raise ValueError(response.text())
        return response

    def load(self):
        request = f"""<wfs:GetFeature
            xmlns:wfs="http://www.opengis.net/wfs"
            service="WFS"
            version="1.1.0"
            xsi:schemaLocation="http://www.opengis.net/wfs
            http://schemas.opengis.net/wfs/1.1.0/wfs.xsd"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            outputFormat="application/json">
            <wfs:Query typeName="wozloket:woz_woz_object" srsName="EPSG:28992" xmlns:WozViewer="http://WozViewer.geonovum.nl" xmlns:ogc="http://www.opengis.net/ogc">
                <ogc:Filter xmlns:ogc="http://www.opengis.net/ogc">
                    <ogc:And>
                        <ogc:PropertyIsEqualTo matchCase="true">
                            <ogc:PropertyName>wobj_bag_obj_id</ogc:PropertyName>
                            <ogc:Literal>{self.id}</ogc:Literal>
                        </ogc:PropertyIsEqualTo>
                    </ogc:And>
                </ogc:Filter>
            </wfs:Query>
        </wfs:GetFeature>"""
        values = {}
        for feature in self.api("woz-proxy/wozloket", data=request).json()["features"]:
            date = datetime.strptime(feature["properties"]["wobj_wrd_ingangsdatum"], "%d-%m-%Y").replace(tzinfo=timezone("Europe/Amsterdam"))
            date.replace(year=date.year - 1)
            values[date] = Decimal(feature["properties"]["wobj_wrd_woz_waarde"])
        return [Account(str(self.id), None, Account.Type.PROPERTY, list(values.values())[0], "WOZ value", "https://www.wozwaardeloket.nl")]
