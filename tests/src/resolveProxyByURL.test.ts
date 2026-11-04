import * as assert from 'assert';
import { createProxyResolver, getOrLoadAdditionalCertificates, loadSystemCertificates, Log, LogLevel, ProxyAgentParams, resetCaches } from '../../src';

function createParams(overrides: Partial<ProxyAgentParams>): ProxyAgentParams {
	const noop = () => { };
	return {
		resolveProxy: async () => undefined,
		getProxyURL: () => undefined,
		getProxySupport: () => 'override',
		getNoProxyConfig: () => [],
		isAdditionalFetchSupportEnabled: () => true,
		isWebSocketPatchEnabled: () => true,
		addCertificatesV1: () => false,
		addCertificatesV2: () => false,
		loadSystemCertificatesFromNode: () => false,
		loadAdditionalCertificates: async () => [],
		log: { trace: noop, debug: noop, info: noop, warn: noop, error: noop },
		getLogLevel: () => LogLevel.Off,
		proxyResolveTelemetry: noop,
		isUseHostProxyEnabled: () => true,
		env: {},
		...overrides,
	};
}

describe('resolveProxyByURL', function () {
	it('preloads Node.js system certificates on macOS', async function () {
		if (process.platform !== 'darwin') {
			this.skip();
		}

		resetCaches();
		const debugMessages: string[] = [];
		const log: Log = {
			trace: () => { },
			debug: message => debugMessages.push(message),
			info: () => { },
			warn: () => { },
			error: () => { },
		};
		const params = createParams({
			addCertificatesV1: () => true,
			loadSystemCertificatesFromNode: () => true,
			loadAdditionalCertificates: () => loadSystemCertificates({
				loadSystemCertificatesFromNode: () => true,
				log,
			}),
			log,
		});
		try {
			createProxyResolver(params);
			const startedDuringResolverCreation = debugMessages.includes('ProxyResolver#loadSystemCertificates starting worker');
			await getOrLoadAdditionalCertificates(params);
			assert.deepStrictEqual({
				startedDuringResolverCreation,
				finishedLoadingSystemCertificates: debugMessages.some(message => message.startsWith('ProxyResolver#loadSystemCertificates from Node.js count')),
			}, {
				startedDuringResolverCreation: true,
				finishedLoadingSystemCertificates: true,
			});
		} finally {
			resetCaches();
		}
	});

	it('reports localhost as a direct connection', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({}));
		assert.deepStrictEqual(await resolveProxyByURL('http://localhost:3000/'), {
			url: undefined, type: 'DIRECT', source: 'localhost', result: 'DIRECT',
		});
	});

	it('reports the http.proxy setting source', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			getProxyURL: () => 'http://proxy.example.com:8080',
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: 'http://proxy.example.com:8080', type: 'PROXY', source: 'setting', result: 'PROXY proxy.example.com:8080',
		});
	});

	it('reports the environment variable source', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			env: { https_proxy: 'https://envproxy.example.com:3128' },
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: 'https://envproxy.example.com:3128', type: 'HTTPS', source: 'env', result: 'HTTPS envproxy.example.com:3128',
		});
	});

	it('honors the no_proxy environment variable', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			env: { https_proxy: 'https://envproxy.example.com:3128', no_proxy: 'example.com' },
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'DIRECT', source: 'noProxyEnv', result: 'DIRECT',
		});
	});

	it('honors the http.noProxy setting over env variables', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			env: { https_proxy: 'https://envproxy.example.com:3128' },
			getNoProxyConfig: () => ['example.com'],
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'DIRECT', source: 'noProxyConfig', result: 'DIRECT',
		});
	});

	it('reports the system/PAC source with the resolved type', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			resolveProxy: async () => 'SOCKS socksproxy.example.com:1080',
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: 'socks://socksproxy.example.com:1080', type: 'SOCKS', source: 'system', result: 'SOCKS socksproxy.example.com:1080',
		});
	});

	it('preserves the unnormalized SOCKS5 and HTTP scheme tokens', async function () {
		const socks5 = createProxyResolver(createParams({
			resolveProxy: async () => 'SOCKS5 socksproxy.example.com:1080',
		}));
		assert.deepStrictEqual(await socks5.resolveProxyByURL('https://example.com/'), {
			url: 'socks://socksproxy.example.com:1080', type: 'SOCKS5', source: 'system', result: 'SOCKS5 socksproxy.example.com:1080',
		});
		const http = createProxyResolver(createParams({
			resolveProxy: async () => 'HTTP proxy.example.com:8080',
		}));
		assert.deepStrictEqual(await http.resolveProxyByURL('https://example.com/'), {
			url: 'http://proxy.example.com:8080', type: 'HTTP', source: 'system', result: 'HTTP proxy.example.com:8080',
		});
	});

	it('reports a direct connection resolved by the system', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			resolveProxy: async () => 'DIRECT',
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'DIRECT', source: 'system', result: 'DIRECT',
		});
	});

	it('reports EMPTY when the system resolver returns nothing', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			resolveProxy: async () => undefined,
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'EMPTY', source: 'system', result: undefined,
		});
	});

	it('reports UNRECOGNIZED when the system result has no known scheme', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			resolveProxy: async () => 'BOGUS proxy.example.com:9999',
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'UNRECOGNIZED', source: 'system', result: 'BOGUS proxy.example.com:9999',
		});
	});

	it('keeps the fallback entries of a system result', async function () {
		const result = 'PROXY proxy1.example.com:8080; HTTPS proxy2.example.com:8443; DIRECT';
		const { resolveProxyByURL } = createProxyResolver(createParams({
			resolveProxy: async () => result,
		}));
		assert.deepStrictEqual([
			await resolveProxyByURL('https://example.com/'),
			await resolveProxyByURL('https://example.com/other'),
		], [
			{ url: 'http://proxy1.example.com:8080', type: 'PROXY', source: 'system', result },
			{ url: 'http://proxy1.example.com:8080', type: 'PROXY', source: 'system_cached', result },
		]);
	});
	it('omits credentials from the result, but not from the url', async function () {
		const setting = createProxyResolver(createParams({
			getProxyURL: () => 'http://user:pass@proxy.example.com:8080',
		}));
		const env = createProxyResolver(createParams({
			env: { https_proxy: 'https://jane%40corp.example.com:p@ss@envproxy.example.com:3128' },
		}));
		const system = createProxyResolver(createParams({
			resolveProxy: async () => 'PROXY user@proxy1.example.com:8080; HTTPS proxy2.example.com:8443; DIRECT',
		}));
		assert.deepStrictEqual([
			await setting.resolveProxyByURL('https://example.com/'),
			await env.resolveProxyByURL('https://example.com/'),
			await system.resolveProxyByURL('https://example.com/'),
		], [
			{ url: 'http://user:pass@proxy.example.com:8080', type: 'PROXY', source: 'setting', result: 'PROXY proxy.example.com:8080' },
			{ url: 'https://jane%40corp.example.com:p@ss@envproxy.example.com:3128', type: 'HTTPS', source: 'env', result: 'HTTPS envproxy.example.com:3128' },
			{ url: 'http://user@proxy1.example.com:8080', type: 'PROXY', source: 'system', result: 'PROXY proxy1.example.com:8080; HTTPS proxy2.example.com:8443; DIRECT' },
		]);
	});

	it('reports remote when host proxy resolution is disabled', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			isUseHostProxyEnabled: () => false,
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'DIRECT', source: 'remote', result: 'DIRECT',
		});
	});
});
