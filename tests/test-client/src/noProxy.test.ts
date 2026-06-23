import * as assert from 'assert';
import * as vpa from '../../..';

describe("no_proxy value support", () => {
    const urlWithDomain = "https://example.com/some/path";
    const urlWithDomainAndPort = "https://example.com:80/some/path";
    const urlWithSubdomain = "https://internal.example.com/some/path";
    const urlWithIPv4 = "https://100.0.0.1/some/path";
    const urlWithIPv4AndPort = "https://100.0.0.1:80/some/path";
    const urlWithIPv6 = "https://[f182:5b41:6491:49d2:2384:cca9:1ba5:13f1]/some/path";

    const baseParams: vpa.ProxyAgentParams = {
        resolveProxy: async () => 'PROXY test-http-proxy:3128',
        getProxyURL: () => undefined,
        getProxySupport: () => 'override',
        isAdditionalFetchSupportEnabled: () => true,
        addCertificatesV1: () => false,
        addCertificatesV2: () => true,
        log: console,
        getLogLevel: () => vpa.LogLevel.Trace,
        proxyResolveTelemetry: () => undefined,
        loadAdditionalCertificates: () => Promise.resolve([]),
        useHostProxy: true,
        env: {},
    };

    const testNoProxy = async (expectedOutcome: 'handled' | 'bypassed', testUrl: string, denyList: string[]) => {
        const { resolveProxyURL } = vpa.createProxyResolver({...baseParams, getNoProxyConfig: () => denyList});
        const resolvedUrl = await resolveProxyURL(testUrl)
        const outcome = resolvedUrl === undefined ? 'bypassed' : 'handled';
        assert.strictEqual(outcome, expectedOutcome, `given a denylist of ${denyList}, proxying ${testUrl} should have been ${expectedOutcome} but was not`);
    }

    it("proceeds if no denylists are provided", async () => {
        await testNoProxy('handled', urlWithDomain, []);
    });

    it("match wildcard", async () => {
        await testNoProxy('bypassed', urlWithDomain, ["*"]);
        await testNoProxy('bypassed', urlWithSubdomain, ["*"]);
        await testNoProxy('bypassed', urlWithIPv4, ["*"]);
        await testNoProxy('bypassed', urlWithIPv6, ["*"]);
    });

    it("match direct hostname", async () => {
        await testNoProxy('bypassed', urlWithDomain, ['example.com']);
        await testNoProxy('handled', urlWithDomain, ['otherexample.com']);
        // Technically the following are a suffix match but it's a known behavior in the ecosystem
        await testNoProxy('bypassed', urlWithDomain, ['.example.com']);
        await testNoProxy('handled', urlWithDomain, ['.otherexample.com']);
    });

    it("match hostname suffixes", async () => {
        await testNoProxy('bypassed', urlWithSubdomain, ['example.com']);
        await testNoProxy('bypassed', urlWithSubdomain, ['.example.com']);
        await testNoProxy('handled', urlWithSubdomain, ['otherexample.com']);
        await testNoProxy('handled', urlWithSubdomain, ['.otherexample.com']);
    });

    it("match hostname with ports", async () => {
        await testNoProxy('bypassed', urlWithDomainAndPort, ['example.com:80']);
        await testNoProxy('handled', urlWithDomainAndPort, ['otherexample.com:80']);
        await testNoProxy('handled', urlWithDomainAndPort, ['example.com:70']);
    });

    it("match IP addresses", async () => {
        await testNoProxy('handled', urlWithIPv4, ['example.com']);
        await testNoProxy('handled', urlWithIPv6, ['example.com']);
        await testNoProxy('bypassed', urlWithIPv4, ['100.0.0.1']);
        await testNoProxy('bypassed', urlWithIPv6, ['f182:5b41:6491:49d2:2384:cca9:1ba5:13f1']);
    });

    it("match IP addresses with port", async () => {
        await testNoProxy('bypassed', urlWithIPv4AndPort, ['100.0.0.1:80']);
        await testNoProxy('handled', urlWithIPv4AndPort, ['100.0.0.1:70']);
    });

    it("match IP addresses with range deny list", async () => {
        await testNoProxy('bypassed', urlWithIPv4, ['100.0.0.0/8']);
        await testNoProxy('handled', urlWithIPv4, ['10.0.0.0/8']);
        await testNoProxy('bypassed', urlWithIPv6, ['f182:5b41:6491:49d2::0/64']);
        await testNoProxy('handled', urlWithIPv6, ['100::0/64']);
    })
});