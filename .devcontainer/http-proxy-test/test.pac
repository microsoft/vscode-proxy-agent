function FindProxyForURL(url, host) {
	if (dnsDomainIs(host, "github.com"))
		return "PROXY 127.0.0.1:3144";
	if (dnsDomainIs(host, "githubcopilot.com"))
		return "PROXY 127.0.0.1:3144";
	return "PROXY 127.0.0.1:3155";
}