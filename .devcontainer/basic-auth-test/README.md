## Basic Auth Test

Use this dev container configuration with a different VS Code install than you want to test (e.g., use VS Code stable if you want to test VS Code Insiders).
- `Dev Containers: Reopen in Container` > `Basic Auth Test`.
- The dev container should show 3 log terminals: 1 for the proxy config (PAC), 2 for 2 proxies with different basic auth credentials.
- Locally start VS Code to test with the PAC file's URL, e.g.: `code-insiders --proxy-pac-url=http://localhost:3333`.
- Enter the credentials when asked: localhost:3111 uses user1 and pass1, localhost:3122 uses user2 and pass2.
	- Connections to *.github.com go through localhost:3111.
	- Connections to *.githubcopilot.com go through localhost:3122.
	- All other connections do not use a proxy.
- Install GitHub Copilot Chat and use `Developer: GitHub Copilot Chat Diagnostics` to test connections with basic auth.
- Verify in the log terminals of the dev container that the PAC file and the proxies are being used.

Optional (from other test passes):
- To further check extension support install https://marketplace.visualstudio.com/items?itemName=chrmarti.network-proxy-test.
	- Update `test.pac` to apply the proxies to different domains, e.g., `https://example.com` and `https://marketplace.visualstudio.com`.
	- Use `Network Proxy Test: Test Network Connection` to test.
- Use `yarn proxy-1:passwd <new password>` and `yarn proxy-2:passwd <new password>` in the dev container to update passwords.
- The 'Remember my credentials' option in the credentials dialog remembers the credentails across restarts.
	- Note that credentials are always remembered until VS Code is restarted (not just reloaded). If you did not check the 'Remember my credentials' option, you will be asked again after restarting VS Code.
