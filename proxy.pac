function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.example.com") ||
        shExpMatch(host, "api.someservice.com") ||
        shExpMatch(host, "cool-ibex-420.convex.cloud")
        ) {
        return "PROXY localhost:8080"; // mitmproxy's default port
    }
    return "DIRECT";
}
