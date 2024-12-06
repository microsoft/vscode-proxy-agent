import * as https from 'https';
import * as tls from 'tls';
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import * as vpa from '../../..';
import { createPacProxyAgent } from '../../../src/agent';
import { testRequest, ca, unusedCa, proxiedProxyAgentParamsV1, tlsProxiedProxyAgentParamsV1, log } from './utils';

describe('Proxied client', function () {
	it('should use HTTP proxy for HTTPS connection', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: createPacProxyAgent(async () => 'PROXY test-http-proxy:3128'),
			ca,
		});
	});

	it('should use HTTPS proxy for HTTPS connection', function () {
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(tlsProxiedProxyAgentParamsV1);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(tlsProxiedProxyAgentParamsV1, https, resolveProxy),
		} as any;
		return testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			_vscodeTestReplaceCaCerts: true,
		});
	});

	it('should use HTTPS proxy for HTTPS connection (fetch)', async function () {
		const { resolveProxyURL } = vpa.createProxyResolver(tlsProxiedProxyAgentParamsV1);
		const patchedFetch = vpa.createFetchPatch(tlsProxiedProxyAgentParamsV1, globalThis.fetch, resolveProxyURL);
		const res = await patchedFetch('https://test-https-server/test-path');
		assert.strictEqual(res.status, 200);
		assert.strictEqual((await res.json()).status, 'OK!');
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
					return lookupProxyAuthorization(log, log, proxyAuthenticateCache, true, proxyURL, proxyAuthenticate, state);
				},
			}),
			ca,
		});
	});
	
	it('should use system certificates', async function () {
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(proxiedProxyAgentParamsV1);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(proxiedProxyAgentParamsV1, https, resolveProxy),
		} as any;
		await testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			_vscodeTestReplaceCaCerts: true,
		});
	});
	it('should use ca request option', async function () {
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(proxiedProxyAgentParamsV1);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(proxiedProxyAgentParamsV1, https, resolveProxy),
		} as any;
		try {
			await testRequest(patchedHttps, {
				hostname: 'test-https-server',
				path: '/test-path',
				_vscodeTestReplaceCaCerts: true,
				ca: unusedCa,
			});
			assert.fail('Expected to fail with self-signed certificate');
		} catch (err: any) {
			assert.strictEqual(err?.message, 'self-signed certificate');
		}
	});
	it('should use ca agent option 1', async function () {
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(proxiedProxyAgentParamsV1);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(proxiedProxyAgentParamsV1, https, resolveProxy),
		} as any;
		try {
			await testRequest(patchedHttps, {
				hostname: 'test-https-server',
				path: '/test-path',
				_vscodeTestReplaceCaCerts: true,
				agent: new https.Agent({ ca: unusedCa }),
			});
			assert.fail('Expected to fail with self-signed certificate');
		} catch (err: any) {
			assert.strictEqual(err?.message, 'self-signed certificate');
		}
	});
	it('should use ca agent option 2', async function () {
		try {
			vpa.resetCaches(); // Allows loadAdditionalCertificates to run again.
			const params = {
				...proxiedProxyAgentParamsV1,
				loadAdditionalCertificates: async () => [
					...await vpa.loadSystemCertificates({ log }),
				],
			};
			const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(params);
			const patchedHttps: typeof https = {
				...https,
				...vpa.createHttpPatch(params, https, resolveProxy),
			} as any;
			await testRequest(patchedHttps, {
				hostname: 'test-https-server',
				path: '/test-path',
				_vscodeTestReplaceCaCerts: true,
				agent: new https.Agent({ ca }),
			});
		} finally {
			vpa.resetCaches(); // Allows loadAdditionalCertificates to run again.
		}
	});
	it('should prefer ca agent option', async function () {
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(proxiedProxyAgentParamsV1);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(proxiedProxyAgentParamsV1, https, resolveProxy),
		} as any;
		await testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			_vscodeTestReplaceCaCerts: true,
			ca: unusedCa,
			agent: new https.Agent({ ca: undefined }),
		});
	});
});

// From microsoft/vscode's proxyResolver.ts:
async function lookupProxyAuthorization(
	extHostLogService: Console,
	mainThreadTelemetry: Console,
	// configProvider: ExtHostConfigProvider,
	proxyAuthenticateCache: Record<string, string | string[] | undefined>,
	isRemote: boolean,
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
	sendTelemetry(mainThreadTelemetry, authenticate, isRemote);
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

type ProxyAuthenticationClassification = {
	owner: 'chrmarti';
	comment: 'Data about proxy authentication requests';
	authenticationType: { classification: 'PublicNonPersonalData'; purpose: 'FeatureInsight'; comment: 'Type of the authentication requested' };
	extensionHostType: { classification: 'SystemMetaData'; purpose: 'FeatureInsight'; comment: 'Type of the extension host' };
};

type ProxyAuthenticationEvent = {
	authenticationType: string;
	extensionHostType: string;
};

let telemetrySent = false;

function sendTelemetry(mainThreadTelemetry: Console, authenticate: string[], isRemote: boolean) {
	if (telemetrySent || !authenticate.length) {
		return;
	}
	telemetrySent = true;

	mainThreadTelemetry.debug('proxyAuthenticationRequest', {
		authenticationType: authenticate.map(a => a.split(' ')[0]).join(','),
		extensionHostType: isRemote ? 'remote' : 'local',
	});
}
