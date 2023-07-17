import * as http from 'http';
import * as https from 'https';
import * as vpa from '../../..';
import createPacProxyAgent from '../../../src/agent';
import { testRequest, ca, directProxyAgentParams } from './utils';
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
			agent: createPacProxyAgent(async () => 'DIRECT'),
			ca,
		});
	});
	it('should omit default port in host header', function () {
		// https://github.com/Microsoft/vscode/issues/65118
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: createPacProxyAgent(async () => 'DIRECT'),
			ca,
		}, {
			assertResult: result => {
				assert.strictEqual(result.headers.host, 'test-https-server');
			}
		});
	});
	it('should fall back to original agent when not proxied', function () {
		// https://github.com/Microsoft/vscode/issues/68531
		let originalAgent = false;
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: createPacProxyAgent(async () => 'DIRECT', {
				originalAgent: new class extends http.Agent {
					addRequest(req: any, opts: any): void {
						originalAgent = true;
						(<any>https.globalAgent).addRequest(req, opts);
					}
				}()
			}),
			ca,
		}, {
			assertResult: () => {
				assert.ok(originalAgent);
			}
		});
	});
	it('should handle `false` as the original agent', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: createPacProxyAgent(async () => 'DIRECT', { originalAgent: false }),
			ca,
		});
	});

	it('should override original agent', async function () {
		// https://github.com/microsoft/vscode/issues/117054
		const resolveProxy = vpa.createProxyResolver(directProxyAgentParams);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(directProxyAgentParams, https, resolveProxy),
		} as any;
		let seen = false;
		await testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new class extends https.Agent {
				addRequest(req: any, opts: any): void {
					seen = true;
					(<any>https.globalAgent).addRequest(req, opts);
				}
			}(),
			ca,
		});
		assert.ok(!seen, 'Original agent called!');
	});
	it('should use original agent 1', async function () {
		// https://github.com/microsoft/vscode/issues/117054 avoiding https://github.com/microsoft/vscode/issues/120354
		const resolveProxy = vpa.createProxyResolver(directProxyAgentParams);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(directProxyAgentParams, https, resolveProxy),
		} as any;
		let seen = false;
		await testRequest(patchedHttps, {
			hostname: '',
			path: '/test-path',
			agent: new class extends https.Agent {
				addRequest(req: any, opts: any): void {
					seen = true;
					(<any>https.globalAgent).addRequest(req, opts);
				}
			}(),
			ca,
		}).catch(() => {}); // Connection failure expected.
		assert.ok(seen, 'Original agent not called!');
	});
	it('should use original agent 2', async function () {
		// https://github.com/microsoft/vscode/issues/117054
		const resolveProxy = vpa.createProxyResolver(directProxyAgentParams);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch({
				...directProxyAgentParams,
				getProxySupport: () => 'fallback',
			}, https, resolveProxy),
		} as any;
		let seen = false;
		await testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new class extends https.Agent {
				addRequest(req: any, opts: any): void {
					seen = true;
					(<any>https.globalAgent).addRequest(req, opts);
				}
			}(),
			ca,
		});
		assert.ok(seen, 'Original agent not called!');
	});
	it('should use original agent 3', async function () {
		const resolveProxy = vpa.createProxyResolver(directProxyAgentParams);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch({
				...directProxyAgentParams,
				getProxySupport: () => 'on',
			}, https, resolveProxy),
		} as any;
		let seen = false;
		await testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new class extends https.Agent {
				addRequest(req: any, opts: any): void {
					seen = true;
					(<any>https.globalAgent).addRequest(req, opts);
				}
			}(),
			ca,
		});
		assert.ok(seen, 'Original agent not called!');
	});
});
