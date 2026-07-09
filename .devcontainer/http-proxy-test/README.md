## HTTP Proxy Test

Use this dev container configuration with a different VS Code install than you want to test (e.g., use VS Code stable if you want to test VS Code Insiders).
- `Dev Containers: Reopen in Container` > `HTTP Proxy Test`.
- The dev container should show 3 log terminals: 1 for the proxy config (PAC), 2 for 2 proxies (no authentication).
- Locally start VS Code to test with the PAC file's URL, e.g.: `code-insiders --proxy-pac-url=http://localhost:4444`.
	- Connections to *.github.com go through 127.0.0.1:3144.
	- Connections to *.githubcopilot.com go through 127.0.0.1:3144.
	- All other connections go through 127.0.0.1:3155.
- Install GitHub Copilot Chat and use `Developer: GitHub Copilot Chat Diagnostics` to test connections.
- Verify in the log terminals of the dev container that the PAC file and the proxies are being used.

Optional (from other test passes):
- To further check extension support install https://marketplace.visualstudio.com/items?itemName=chrmarti.network-proxy-test.
	- Update `test.pac` to apply the proxies to different domains, e.g., `https://example.com` and `https://marketplace.visualstudio.com`.
	- Use `Network Proxy Test: Test Network Connection` to test.
