function FindProxyForURL(url, host) {
	if (dnsDomainIs(host, "github.com"))
		return "PROXY localhost:3111";
	if (dnsDomainIs(host, "githubcopilot.com"))
		return "PROXY localhost:3122";
	return "DIRECT";
}