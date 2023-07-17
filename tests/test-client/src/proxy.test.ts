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

	it('should work with kerberos', function () {
		this.timeout(10000);
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: createPacProxyAgent(async () => 'PROXY test-http-kerberos-proxy:80', {
				async lookupProxyAuthorization(proxyURL, proxyAuthenticate) {
					assert.strictEqual(proxyURL, 'http://test-http-kerberos-proxy/');
					if (!proxyAuthenticate) {
						return;
					}
					assert.strictEqual(proxyAuthenticate, 'Negotiate');

					if (proxyAuthenticate.startsWith('Negotiate')) {
						const kerberos = await import('kerberos');
						const url = new URL(proxyURL);
						const spn = process.platform === 'win32' ? `HTTP/${url.host}` : `HTTP@${url.host}`;
						const client = await kerberos.initializeClient(spn);
						const response = await client.step('');
						return 'Negotiate ' + response;
					}
					return undefined;
				},
			}),
			ca,
		});
	});
});
