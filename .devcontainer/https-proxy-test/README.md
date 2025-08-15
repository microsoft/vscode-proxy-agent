## HTTPS Proxy Test

- `Dev Containers: Reopen in Container` > `HTTPS Proxy Test`.
- First time: Install the certificate from `.devcontainer/https-proxy-test/mitmproxy-config` in the OS and restart VS Code. See https://docs.mitmproxy.org/stable/concepts-certificates/#installing-the-mitmproxy-ca-certificate-manually.
- Add the user setting `"http.proxy": "https://localhost:8080"`.
- Install GitHub Copilot Chat and use `Developer: GitHub Copilot Chat Diagnostics` to test connections with a HTTPS proxy. Use a second window to test connections from a local extension host.
- Verify in the log terminal of the dev container that the proxy is being used.

Note: Due to an issue in mitmproxy (https://github.com/python-hyper/h2/issues/319), Electron's `fetch` currently doesn't work. Add the user setting `"github.copilot.advanced.debug.useElectronFetcher": false` as a workaround.