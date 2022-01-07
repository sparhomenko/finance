from datetime import datetime
from decimal import Decimal
from zoneinfo import ZoneInfo

from more_itertools import last, one
from requests import Session
from requests.models import Response

from finance.core import Account, Transaction
from finance.typesafe import JSON


class Property:
    def __init__(self, query: str):
        self.query = query
        self.session = Session()
        self.api("")
        doc = one(JSON.response(self.api("api/geocoder/v3/suggest", params={"query": query}))["docs"])
        address = JSON.response(self.api("api/geocoder/v3/lookup", params={"id": doc["id"].str}))
        self.id = int(address["adresseerbaarobject_id"].str)
        self.value: dict[int, Decimal] = {}

    def api(self, endpoint: str, params: dict[str, str] | None = None, data: str | None = None) -> Response:
        method = "POST" if data else "GET"
        response = self.session.request(method, f"https://www.wozwaardeloket.nl/{endpoint}", params=params, data=data)
        response.raise_for_status()
        return response

    def load(self) -> list[Account]:
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
        for feature in JSON.response(self.api("woz-proxy/wozloket", data=request))["features"]:
            date = feature["properties"]["wobj_wrd_ingangsdatum"].strptime("%d-%m-%Y").replace(tzinfo=ZoneInfo("Europe/Amsterdam"))
            self.value[date.year - 1] = feature["properties"]["wobj_wrd_woz_waarde"].decimal
        self.value = dict(sorted(self.value.items()))
        account = Account(str(self.id), self.query, Account.Type.PROPERTY, last(self.value.values()), "WOZ value", "https://www.wozwaardeloket.nl")
        last_value = Decimal(0)
        for year, value in self.value.items():
            Transaction(datetime(year, 1, 1, tzinfo=ZoneInfo("Europe/Amsterdam")), "WOZ value", None, [Transaction.Line(account, value - last_value)]).complete(must_have=True)
            last_value = value
        return [account]
