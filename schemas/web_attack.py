from pydantic import BaseModel, HttpUrl


class WebAttackInput(BaseModel):
    target_url: HttpUrl
    cookie: str | None = None