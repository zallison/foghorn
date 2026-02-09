from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse


def _register_static_routes(
    app: FastAPI, web_cfg: Dict[str, Any], www_root: str, auth_dep: Any
) -> None:
    """Register index and static-file routes.

    Inputs:
      - app: FastAPI application instance.
      - web_cfg: Webserver configuration mapping.
      - www_root: Resolved www_root path from create_app.
      - auth_dep: FastAPI dependency for authentication (unused; kept for
        symmetry with other registration helpers).

    Outputs:
      - None (routes are registered on the app).
    """

    index_enabled = bool(web_cfg.get("index", True))

    @app.get("/index.html", response_class=HTMLResponse)
    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        """Serve html/index.html for root and index when enabled.

        Inputs: none
        Outputs: HTMLResponse when enabled and index.html exists; otherwise 404.
        """

        if not index_enabled:
            raise HTTPException(
                status_code=404,
                detail="index disabled",
            )

        www_root_local = getattr(app.state, "www_root", www_root)
        index_path = os.path.abspath(os.path.join(www_root_local, "index.html"))
        if not os.path.isfile(index_path):
            raise HTTPException(
                status_code=404,
                detail="index not found",
            )
        return FileResponse(index_path)

    @app.get("/{path:path}")
    async def static_www(path: str) -> Any:
        """Serve files from the project-level html/ directory when they exist.

        Inputs:
          - path: Requested path segment (e.g., "logo.png" or "css/app.css").

        Outputs:
          - FileResponse when the file exists under html/, otherwise 404.
        """

        if not path:
            raise HTTPException(status_code=404, detail="not found")

        www_root_local = getattr(app.state, "www_root", www_root)
        root_abs = os.path.abspath(www_root_local)
        candidate = os.path.abspath(os.path.join(root_abs, path))

        # Simple path traversal protection: require candidate under html root.
        if not candidate.startswith(root_abs + os.sep):
            raise HTTPException(status_code=404, detail="not found")
        if not os.path.isfile(candidate):
            raise HTTPException(status_code=404, detail="not found")

        return FileResponse(candidate)
