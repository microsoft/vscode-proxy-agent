import * as https from 'https';
import { ClientRequest, RequestOptions } from 'http';
import * as vpa from '../../..';
import { testRequest, ca } from './utils';
import * as assert from 'assert';

describe('Direct client', function () {
	it('should work without agent', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			ca,
		});
	});
	it('should support SNI when not proxied', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new vpa.ProxyAgent({
				resolveProxy: (req: ClientRequest, opts: RequestOptions, url: string, cb: (res: string) => void) => cb('DIRECT'),
				defaultPort: 443
			}),
			ca,
		});
	});
	it('should omit default port in host header', function () {
		// https://github.com/Microsoft/vscode/issues/65118
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new vpa.ProxyAgent({
				resolveProxy: (req: ClientRequest, opts: RequestOptions, url: string, cb: (res: string) => void) => cb('DIRECT'),
				defaultPort: 443
			}),
			ca,
		}, {
			assertResult: result => {
				assert.strictEqual(result.headers.host, 'test-https-server');
			}
		});
	});
	it('should fall back to original agent when not proxied', function () {
		// https://github.com/Microsoft/vscode/issues/68531
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new vpa.ProxyAgent({
				resolveProxy: (req: ClientRequest, opts: RequestOptions, url: string, cb: (res: string) => void) => cb('DIRECT'),
				defaultPort: 443,
				originalAgent: {
					addRequest: (req: any, opts: any) => {
						req.setHeader('original-agent', 'true');
						(<any>https.globalAgent).addRequest(req, opts);
					}
				} as any
			}),
			ca,
		}, {
			assertResult: result => {
				assert.strictEqual(result.headers['original-agent'], 'true');
			}
		});
	});
	it('should handle `false` as the original agent', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new vpa.ProxyAgent({
				resolveProxy: (req: ClientRequest, opts: RequestOptions, url: string, cb: (res: string) => void) => cb('DIRECT'),
				defaultPort: 443,
				originalAgent: false
			}),
			ca,
		});
	});

	const directProxyAgentParams = {
		resolveProxy: async () => 'DIRECT',
		getHttpProxySetting: () => undefined,
		log: (level: vpa.LogLevel, message: string, ...args: any[]) => level >= vpa.LogLevel.Debug && console.log(message, ...args),
		getLogLevel: () => vpa.LogLevel.Debug,
		proxyResolveTelemetry: () => undefined,
		useHostProxy: true,
		env: {},
	};
	it('should use original agent', async function () {
		// https://github.com/microsoft/vscode/issues/120354 (superseding https://github.com/microsoft/vscode/issues/117054)
		const resolveProxy = vpa.createProxyResolver(directProxyAgentParams);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(https, resolveProxy, { config: 'override' }, { config: false }, false),
		} as any;
		let seen = false;
		await testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: {
				defaultPort: 443, // This is required to support request options without port/defaultPort.
				addRequest: (req: any, opts: any) => {
					seen = true;
					(<any>https.globalAgent).addRequest(req, opts);
				}
			} as any,
			ca,
		});
		assert.ok(seen, 'Original agent not called!');
	});
	it('should use original agent', async function () {
		const resolveProxy = vpa.createProxyResolver(directProxyAgentParams);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(https, resolveProxy, { config: 'on' }, { config: false }, false),
		} as any;
		let seen = false;
		await testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: {
				addRequest: (req: any, opts: any) => {
					seen = true;
					(<any>https.globalAgent).addRequest(req, opts);
				}
			} as any,
			ca,
		});
		assert.ok(seen, 'Original agent not called!');
	});
});
