# Change Log
Notable changes will be documented here.

## [0.32.0]
- Check both system certificates settings for `fetch` ([microsoft/vscode-proxy-agent#66](https://github.com/microsoft/vscode-proxy-agent/pull/66))

## [0.31.0]
- Fix basic auth for fetch ([microsoft/vscode#239033](https://github.com/microsoft/vscode/issues/239033))

## [0.30.0]
- useHostProxy > isUseHostProxyEnabled() ([microsoft/vscode-copilot-release#3821](https://github.com/microsoft/vscode-copilot-release/issues/3821))

## [0.29.0]
- Update to undici 7.2.0 ([microsoft/vscode-proxy-agent#57](https://github.com/microsoft/vscode-proxy-agent/pull/57))
- Get options from unpatched agents ([microsoft/vscode-proxy-agent#58](https://github.com/microsoft/vscode-proxy-agent/pull/58))

## [0.28.0]
- Pass-through with socketPath ([microsoft/vscode#236423](https://github.com/microsoft/vscode/issues/236423))

## [0.27.0]
- Add system certificates to https proxy requests ([microsoft/vscode#235410](https://github.com/microsoft/vscode/issues/235410))

## [0.26.0]
- Move fetch patching to agent package ([microsoft/vscode#228697](https://github.com/microsoft/vscode/issues/228697))

## [0.25.0]
- Do not overwrite https.Agent certificates ([microsoft/vscode#234175](https://github.com/microsoft/vscode/issues/234175))

## [0.24.0]
- Skip keepAlive flag ([microsoft/vscode#228872](https://github.com/microsoft/vscode/issues/228872))
- Refactor for reuse with fetch ([microsoft/vscode#228697](https://github.com/microsoft/vscode/issues/228697))

## [0.23.0]
- Pass on keepAlive flag ([microsoft/vscode#173861](https://github.com/microsoft/vscode/issues/173861))

## [0.22.0]
- Set agent protocol ([microsoft/vscode-extension-test-runner#42](https://github.com/microsoft/vscode-extension-test-runner/issues/42))

## [0.21.0]
- Add NO_PROXY setting to be passed from config ([microsoft/vscode#211956](https://github.com/microsoft/vscode/issues/211956))

## [0.20.0]
- Update socks to avoid CVE-2024-29415

## [0.19.0]
- Also check for /etc/ssl/ca-bundle.pem ([microsoft/vscode#203847](https://github.com/microsoft/vscode/issues/203847))

## [0.18.0]
- Async callback for additional certificates ([microsoft/vscode-remote-release#9176](https://github.com/microsoft/vscode-remote-release/issues/9176))

## [0.17.0]
- Add auth callback and Kerberos test setup ([microsoft/vscode#187456](https://github.com/microsoft/vscode/issues/187456))

## [0.16.0]
- Update dependencies.

## [0.15.0]
- Skip expired certificates ([microsoft/vscode#184271](https://github.com/microsoft/vscode/issues/184271))
- Handle additional socks schemes ([microsoft/vscode#158669](https://github.com/microsoft/vscode/issues/158669))
- Ensure early writes are queued ([microsoft/vscode#185098](https://github.com/microsoft/vscode/issues/185098))

## [0.14.1]
- Load certificates in net.connect ([microsoft/vscode#185098](https://github.com/microsoft/vscode/issues/185098))

## [0.14.0]
- Load certificates in tls.connect ([microsoft/vscode#185098](https://github.com/microsoft/vscode/issues/185098))

## [0.13.0]
- Rename to @vscode/proxy-agent.

## [0.12.0]
- Avoid buffer deprecation warning (fixes [microsoft/vscode#136874](https://github.com/microsoft/vscode/issues/136874))

## [0.11.0]
- Override original agent again (fixes [microsoft/vscode#117054](https://github.com/microsoft/vscode/issues/117054))

## [0.10.0]
- Do not override original agent (forward port [microsoft/vscode#120354](https://github.com/microsoft/vscode/issues/120354))
- Move vscode-windows-ca-certs dependency ([microsoft/vscode#120546](https://github.com/microsoft/vscode/issues/120546))

## [0.9.0]
- Copy and adapt pac-proxy-agent to catch up with latest dependencies and bug fixes.

## [0.8.2]
- Do not override original agent (fixes [microsoft/vscode#120354](https://github.com/microsoft/vscode/issues/120354))

## [0.8.0]
- Align log level constants with VS Code.

## [0.7.0]
- Override original agent (fixes [microsoft/vscode#117054](https://github.com/microsoft/vscode/issues/117054))

## [0.6.0]
- Use TypeScript.
- Move proxy resolution from VS Code here.

## [0.5.2]
- Handle false as the original proxy.
- Update typings.

## [0.5.1]
- Allow for newer patch versions of dependencies.

## [0.5.0]
- Update to https-proxy-agent 2.2.3 (https://nodesecurity.io/advisories/1184)

## [0.4.0]
- Fall back to original agent when provided in options.
- Add default port to options.

## [0.3.0]
- Forward request and options to `resolveProxy`.

## [0.2.0]
- Fix missing servername for SNI ([#27](https://github.com/Microsoft/vscode/issues/64133)).

## [0.1.0]
- Initial release