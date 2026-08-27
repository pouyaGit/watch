from pymongo import MongoClient

from ai.schemas.http import HTTPAsset


class HTTPCollector:
    def __init__(
        self,
        uri: str,
        database: str = "watch",
        collection: str = "http",
        timeout_ms: int = 5000,
    ):
        self.client = MongoClient(
            uri,
            serverSelectionTimeoutMS=timeout_ms,
        )

        self.db = self.client[database]
        self.collection = self.db[collection]

    def ping(self) -> bool:
        self.client.admin.command("ping")
        return True

    def all(self) -> list[HTTPAsset]:
        assets = []

        cursor = self.collection.find(
            {},
            {
                "_id": 0,
                "program_name": 1,
                "subdomain": 1,
                "scope": 1,
                "tech": 1,
                "title": 1,
                "status_code": 1,
                "url": 1,
                "final_url": 1,
            },
        )

        for doc in cursor:
            assets.append(
                HTTPAsset(
                    program_name=doc.get("program_name", ""),
                    subdomain=doc.get("subdomain", ""),
                    scope=doc.get("scope", ""),
                    tech=doc.get("tech", []),
                    title=doc.get("title"),
                    status_code=doc.get("status_code"),
                    url=doc.get("url"),
                    final_url=doc.get("final_url"),
                )
            )

        return assets

    def close(self):
        self.client.close()