import uvicorn

from app.factory import bootstrap
from app.web.app import create_app

settings, repository = bootstrap("config/vpswatch.yml")

app = create_app(settings, repository)
app.state.config_path = "config/vpswatch.yml"

# Localhost only: the dashboard is served through the nginx /pkill
# reverse proxy over HTTPS; the raw port must not face the internet.
uvicorn.run(
    app,
    host="127.0.0.1",
    port=42496,
)
