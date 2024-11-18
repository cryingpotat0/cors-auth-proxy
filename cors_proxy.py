from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    flow.response.headers["Access-Control-Allow-Origin"] = "*"
    flow.response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    flow.response.headers["Access-Control-Allow-Headers"] = "*"
    flow.response.headers["Access-Control-Allow-Credentials"] = "true"
    flow.response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    flow.response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

    print(f"Proxied: {flow.request.url}")
    print(f"Response headers: {flow.response.headers}")
