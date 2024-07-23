## Basic Auth Test

Use this dev container configuration with a different VS Code install than you want to test (e.g., use VS Code stable if you want to test VS Code Insiders).
- `Dev Containers: Reopen in Container` > `Basic Auth Test`.
- The dev container should show 3 log terminals: 1 for the proxy config (PAC), 2 for 2 proxies with different basic auth credentials.
- Locally start VS Code to test with the PAC file's URL, e.g.: `code-insiders --proxy-pac-url=http://localhost:3333`.
- Enter the credentials when asked: localhost:3111 uses user1 and pass1, localhost:3122 uses user2 and pass2.
	- Connections to marketplace.visualstudio.com (e.g., when searching in the Extensions view) go through localhost:3111.
	- All other connections go through localhost:3122.
- To check extension support for basic auth proxies install https://marketplace.visualstudio.com/items?itemName=chrmarti.network-proxy-test.
	- Use `Network Proxy Test: Test Network Connection` to test, e.g., `https://example.com` and `https://marketplace.visualstudio.com`.
- Verify in the log terminals of the dev container that the PAC file and the proxies are being used.
- To check that Electron's network stack for basic auth proxies is working, search for and install an extension from the Extensions view.
- Use `yarn proxy-1:passwd <new password>` and `yarn proxy-2:passwd <new password>` in the dev container to update passwords.
- Check that the 'Remember my credentials' option in the credentials dialog works as expected.
