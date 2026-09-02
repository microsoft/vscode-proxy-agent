import * as assert from 'assert';
import { createProxyResolver, LogLevel, ProxyAgentParams, resetCaches } from '../../src';

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
		let resolveLoaded: (() => void) | undefined;
		const loaded = new Promise<void>(resolve => resolveLoaded = resolve);
		try {
			createProxyResolver(createParams({
				addCertificatesV1: () => true,
				loadSystemCertificatesFromNode: () => true,
				loadAdditionalCertificates: async () => {
					resolveLoaded?.();
					return [];
				},
			}));
			await loaded;
		} finally {
			resetCaches();
		}
	});

	it('reports localhost as a direct connection', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({}));
		assert.deepStrictEqual(await resolveProxyByURL('http://localhost:3000/'), {
			url: undefined, type: 'DIRECT', source: 'localhost',
		});
	});

	it('reports the http.proxy setting source', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			getProxyURL: () => 'http://proxy.example.com:8080',
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: 'http://proxy.example.com:8080', type: 'PROXY', source: 'setting',
		});
	});

	it('reports the environment variable source', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			env: { https_proxy: 'https://envproxy.example.com:3128' },
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: 'https://envproxy.example.com:3128', type: 'HTTPS', source: 'env',
		});
	});

	it('honors the no_proxy environment variable', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			env: { https_proxy: 'https://envproxy.example.com:3128', no_proxy: 'example.com' },
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'DIRECT', source: 'noProxyEnv',
		});
	});

	it('honors the http.noProxy setting over env variables', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			env: { https_proxy: 'https://envproxy.example.com:3128' },
			getNoProxyConfig: () => ['example.com'],
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'DIRECT', source: 'noProxyConfig',
		});
	});

	it('reports the system/PAC source with the resolved type', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			resolveProxy: async () => 'SOCKS socksproxy.example.com:1080',
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: 'socks://socksproxy.example.com:1080', type: 'SOCKS', source: 'system',
		});
	});

	it('preserves the unnormalized SOCKS5 and HTTP scheme tokens', async function () {
		const socks5 = createProxyResolver(createParams({
			resolveProxy: async () => 'SOCKS5 socksproxy.example.com:1080',
		}));
		assert.deepStrictEqual(await socks5.resolveProxyByURL('https://example.com/'), {
			url: 'socks://socksproxy.example.com:1080', type: 'SOCKS5', source: 'system',
		});
		const http = createProxyResolver(createParams({
			resolveProxy: async () => 'HTTP proxy.example.com:8080',
		}));
		assert.deepStrictEqual(await http.resolveProxyByURL('https://example.com/'), {
			url: 'http://proxy.example.com:8080', type: 'HTTP', source: 'system',
		});
	});

	it('reports a direct connection resolved by the system', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			resolveProxy: async () => 'DIRECT',
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'DIRECT', source: 'system',
		});
	});

	it('reports EMPTY when the system resolver returns nothing', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			resolveProxy: async () => undefined,
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'EMPTY', source: 'system',
		});
	});

	it('reports UNRECOGNIZED when the system result has no known scheme', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			resolveProxy: async () => 'BOGUS proxy.example.com:9999',
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'UNRECOGNIZED', source: 'system',
		});
	});

	it('reports remote when host proxy resolution is disabled', async function () {
		const { resolveProxyByURL } = createProxyResolver(createParams({
			isUseHostProxyEnabled: () => false,
		}));
		assert.deepStrictEqual(await resolveProxyByURL('https://example.com/'), {
			url: undefined, type: 'DIRECT', source: 'remote',
		});
	});
});
