## Squid HTTPS Test

A second TLS-intercepting proxy (in addition to the mitmproxy-based `HTTPS Proxy Test`), using Squid with SSL-Bump behind stunnel.

Squid can only do SSL-Bump on an explicit HTTP `http_port` (it bumps the tunneled TLS of each `CONNECT`), not on an explicit TLS `https_port`. To still expose a real TLS proxy port, stunnel terminates TLS on port `3128` and forwards the decrypted proxy traffic to Squid's localhost-only `http_port`, where SSL-Bump intercepts the connections. A single CA signs both the proxy's `localhost` certificate and the per-host certificates Squid generates, so you only install one certificate on the host.

- `Dev Containers: Reopen in Container` > `Squid HTTPS Test`.
- The dev container should show two log terminals: one for Squid and one for stunnel (the TLS proxy port).
- First time: Install the CA certificate from `.devcontainer/squid-https-test/squid-ssl/ca.crt` in the OS trust store and restart VS Code. The certificate is generated on the first container start, so it only appears after the container is up.
- Add the user setting `"http.proxy": "https://localhost:3133"`.
- Install GitHub Copilot Chat and use `Developer: GitHub Copilot Chat Diagnostics` to test connections with a HTTPS proxy. Use a second window to test connections from a local extension host.
- Verify in the log terminals of the dev container that the proxy is being used.
