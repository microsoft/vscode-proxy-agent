import * as https from 'https';
import * as assert from 'assert';
import createPacProxyAgent from '../../../src/agent';
import { testRequest, ca } from './utils';

describe('Proxied client', function () {
	it('should use HTTP proxy for HTTPS connection', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: createPacProxyAgent(async () => 'PROXY test-http-proxy:3128'),
			ca,
		});
	});

	it('should support basic auth', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: createPacProxyAgent(async () => 'PROXY foo:bar@test-http-auth-proxy:3128'),
			ca,
		});
	});

	it('should fail with 407 when auth is missing', async function () {
		try {
			await testRequest(https, {
				hostname: 'test-https-server',
				path: '/test-path',
				agent: createPacProxyAgent(async () => 'PROXY test-http-auth-proxy:3128'),
				ca,
			});
		} catch (err) {
			assert.strictEqual((err as any).statusCode, 407);
			return;
		}
		assert.fail('Should have failed');
	});

	it('should call auth callback after 407', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: createPacProxyAgent(async () => 'PROXY test-http-auth-proxy:3128', {
				async lookupProxyAuthorization(proxyURL, proxyAuthenticate) {
					assert.strictEqual(proxyURL, 'http://test-http-auth-proxy:3128/');
					if (!proxyAuthenticate) {
						return;
					}
					assert.strictEqual(proxyAuthenticate, 'Basic realm="Squid Basic Authentication"');
					return `Basic ${Buffer.from('foo:bar').toString('base64')}`;
				},
			}),
			ca,
		});
	});

	it('should call auth callback before request', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: createPacProxyAgent(async () => 'PROXY test-http-auth-proxy:3128', {
				async lookupProxyAuthorization(proxyURL, proxyAuthenticate) {
					assert.strictEqual(proxyURL, 'http://test-http-auth-proxy:3128/');
					assert.strictEqual(proxyAuthenticate, undefined);
					return `Basic ${Buffer.from('foo:bar').toString('base64')}`;
				},
			}),
			ca,
		});
	});

	it('should pass state around', async function () {
		let count = 0;
		await testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: createPacProxyAgent(async () => 'PROXY test-http-auth-proxy:3128', {
				async lookupProxyAuthorization(proxyURL, proxyAuthenticate, state: { count?: number }) {
					assert.strictEqual(proxyURL, 'http://test-http-auth-proxy:3128/');
					assert.strictEqual(proxyAuthenticate, state.count ? 'Basic realm="Squid Basic Authentication"' : undefined);
					const credentials = state.count === 2 ? 'foo:bar' : 'foo:wrong';
					count = state.count = (state.count || 0) + 1;
					return `Basic ${Buffer.from(credentials).toString('base64')}`;
				},
			}),
			ca,
		});
		assert.strictEqual(count, 3);
	});

	it('should work with kerberos', function () {
		this.timeout(10000);
		const proxyAuthenticateCache = {};
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: createPacProxyAgent(async () => 'PROXY test-http-kerberos-proxy:80', {
				async lookupProxyAuthorization(proxyURL, proxyAuthenticate, state) {
					assert.strictEqual(proxyURL, 'http://test-http-kerberos-proxy/');
					if (proxyAuthenticate) {
						assert.strictEqual(proxyAuthenticate, 'Negotiate');
					}
					return lookupProxyAuthorization({ ...console, trace: console.log }, proxyAuthenticateCache, proxyURL, proxyAuthenticate, state);
				},
			}),
			ca,
		});
	});
});

// From microsoft/vscode's proxyResolver.ts:
async function lookupProxyAuthorization(
	extHostLogService: Console,
	// configProvider: ExtHostConfigProvider,
	proxyAuthenticateCache: Record<string, string | string[] | undefined>,
	proxyURL: string,
	proxyAuthenticate: string | string[] | undefined,
	state: { kerberosRequested?: boolean }
): Promise<string | undefined> {
	const cached = proxyAuthenticateCache[proxyURL];
	if (proxyAuthenticate) {
		proxyAuthenticateCache[proxyURL] = proxyAuthenticate;
	}
	extHostLogService.trace('ProxyResolver#lookupProxyAuthorization callback', `proxyURL:${proxyURL}`, `proxyAuthenticate:${proxyAuthenticate}`, `proxyAuthenticateCache:${cached}`);
	const header = proxyAuthenticate || cached;
	const authenticate = Array.isArray(header) ? header : typeof header === 'string' ? [header] : [];
	if (authenticate.some(a => /^(Negotiate|Kerberos)( |$)/i.test(a)) && !state.kerberosRequested) {
		try {
			state.kerberosRequested = true;
			const kerberos = await import('kerberos');
			const url = new URL(proxyURL);
			const spn = /* configProvider.getConfiguration('http').get<string>('proxyKerberosServicePrincipal')
				|| */ (process.platform === 'win32' ? `HTTP/${url.hostname}` : `HTTP@${url.hostname}`);
			extHostLogService.debug('ProxyResolver#lookupProxyAuthorization Kerberos authentication lookup', `proxyURL:${proxyURL}`, `spn:${spn}`);
			const client = await kerberos.initializeClient(spn);
			const response = await client.step('');
			return 'Negotiate ' + response;
		} catch (err) {
			extHostLogService.error('ProxyResolver#lookupProxyAuthorization Kerberos authentication failed', err);
		}
	}
	return undefined;
}
