import uvicorn

from app.factory import bootstrap
from app.web.app import create_app

settings, repository = bootstrap("config/vpswatch.yml")

app = create_app(settings, repository)

uvicorn.run(
    app,
    host="0.0.0.0",
    port=42496,
)
