from datetime import datetime
from decimal import Decimal
from zoneinfo import ZoneInfo

from more_itertools import last, one
from requests import Session
from requests.models import Response

from finance.core import Account, AccountType, Line, Transaction
from finance.typesafe import JSON


class Property:
    def __init__(self, query: str):
        self._query = query
        self._session = Session()
        self._api("")
        doc = one(JSON.response(self._api("api/geocoder/v3/suggest", query={"query": query}))["docs"])
        address = JSON.response(self._api("api/geocoder/v3/lookup", query={"id": doc["id"].str}))
        self._id = int(address["adresseerbaarobject_id"].str)
        self.valuation: dict[int, Decimal] = {}

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
                            <ogc:Literal>{self._id}</ogc:Literal>
                        </ogc:PropertyIsEqualTo>
                    </ogc:And>
                </ogc:Filter>
            </wfs:Query>
        </wfs:GetFeature>"""
        for feature in JSON.response(self._api("woz-proxy/wozloket", body=request))["features"]:
            date = feature["properties"]["wobj_wrd_ingangsdatum"].strptime("%d-%m-%Y").replace(tzinfo=ZoneInfo("Europe/Amsterdam"))
            self.valuation[date.year - 1] = feature["properties"]["wobj_wrd_woz_waarde"].decimal
        self.valuation = dict(sorted(self.valuation.items()))
        account = Account(str(self._id), self._query, AccountType.PROPERTY, last(self.valuation.values()), "WOZ value", "https://www.wozwaardeloket.nl")
        last_valuation = Decimal(0)
        for year, valuation in self.valuation.items():
            Transaction(datetime(year, 1, 1, tzinfo=ZoneInfo("Europe/Amsterdam")), "WOZ value", None, [Line(account, valuation - last_valuation)]).complete(must_have=True)
            last_valuation = valuation
        return [account]

    def _api(self, endpoint: str, query: dict[str, str] | None = None, body: str | None = None) -> Response:
        method = "POST" if body else "GET"
        response = self._session.request(method, f"https://www.wozwaardeloket.nl/{endpoint}", params=query, data=body)
        response.raise_for_status()
        return response
