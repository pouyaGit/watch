from collections import defaultdict

from ai.schemas.http import HTTPAsset
from ai.correlator.technology import normalize


class TechnologyIndex:
    def __init__(self, assets: list[HTTPAsset]):
        self.assets_by_technology: dict[str, list[HTTPAsset]] = (
            defaultdict(list)
        )

        for asset in assets:
            seen = set()

            for technology in asset.tech:
                key = normalize(technology)

                if not key or key in seen:
                    continue

                seen.add(key)
                self.assets_by_technology[key].append(asset)

    def get(self, technology: str) -> list[HTTPAsset]:
        return self.assets_by_technology.get(
            normalize(technology),
            [],
        )

    def technologies(self) -> list[str]:
        return sorted(self.assets_by_technology.keys())