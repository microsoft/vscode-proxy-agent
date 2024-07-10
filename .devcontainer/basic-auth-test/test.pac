function FindProxyForURL(url, host) {
	if (dnsDomainIs(host, "marketplace.visualstudio.com"))
		return "PROXY localhost:3111";
	return "PROXY localhost:3122";
}