# VS Code container with network proxy

This is a Dev Container with VS Code Insiders installed and no direct internet connection. HTTP_PROXY and HTTPS_PROXY environment variables are set to the proxy server running in a separate container.

When connecting from a local VS Code window use `VSCODE_IPC_HOOK_CLI= /usr/bin/code-insiders` in the integrated terminal to avoid connecting back to the local window. The Dev Containers extensions automatically forwards the X11 display if available locally.

Or use the Dev Container CLI for tunnels:
```sh
npm i -g @devcontainers/cli
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . code-insiders tunnel
```
