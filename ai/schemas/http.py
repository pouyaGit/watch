from pydantic import BaseModel, Field


class HTTPAsset(BaseModel):
    program_name: str
    subdomain: str
    scope: str

    tech: list[str] = Field(default_factory=list)

    title: str | None = None
    status_code: int | None = None

    url: str | None = None
    final_url: str | None = None