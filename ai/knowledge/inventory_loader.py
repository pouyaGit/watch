from database.db import (
    Http,
    Urls,
    Endpoints,
    Subdomains,
)

from ai.researcher.target_intelligence import (
    HttpRecord,
    UrlRecord,
    EndpointRecord,
    SubdomainRecord,
)

from ai.knowledge.observed_inventory import build_observed_inventory


def load_program_inventory_records(program: str) -> dict:
    return {
        "http_records": [
            HttpRecord.from_document(x)
            for x in Http.objects(program_name=program)
        ],

        "url_records": [
            UrlRecord.from_document(x)
            for x in Urls.objects(program_name=program)
        ],

        "endpoint_records": [
            EndpointRecord.from_document(x)
            for x in Endpoints.objects(program_name=program)
        ],

        "subdomain_records": [
            SubdomainRecord.from_document(x)
            for x in Subdomains.objects(program_name=program)
        ],
    }


def build_real_observed_inventory(program: str):
    return build_observed_inventory(
        program,
        **load_program_inventory_records(program),
    )