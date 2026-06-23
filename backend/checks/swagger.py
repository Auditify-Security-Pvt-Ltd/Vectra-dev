from __future__ import annotations

"""Detect exposed Swagger / OpenAPI documentation."""

import aiohttp
from .base import finding, get

_PATHS = [
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger/",
    "/swagger/index.html",
    "/api-docs",
    "/api-docs/",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi",
    "/api/swagger-ui.html",
    "/api/docs",
    "/docs/",
    "/redoc",
    "/redoc.html",
    "/graphql",
    "/graphiql",
    "/playground",
]

_SWAGGER_MARKERS = [
    "swagger-ui", "swaggerUi", "Swagger UI",
    "openapi", "OpenAPI",
    '"swagger":', '"openapi":',
    "graphql", "GraphQL",
    "redoc",
]


async def run(url: str, session: aiohttp.ClientSession) -> list[dict]:
    base = url.rstrip("/")
    findings = []

    for path in _PATHS:
        probe_url = base + path
        resp, body = await get(session, probe_url)
        if resp is None or body is None:
            continue
        if resp.status not in (200, 206):
            continue
        if not any(m.lower() in body.lower() for m in _SWAGGER_MARKERS):
            continue
        findings.append(finding(
            title="Exposed API Documentation (Swagger/OpenAPI)",
            severity="medium",
            template="vectra-swagger-exposure",
            url=url,
            matched_at=probe_url,
            description=(
                f"API documentation is publicly accessible at {probe_url}. "
                "Exposed API specs reveal endpoints, parameters, and authentication schemes to attackers."
            ),
        ))
        break  # one finding per asset

    return findings
