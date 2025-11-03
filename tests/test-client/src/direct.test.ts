import * as http from 'http';
import * as https from 'https';
import * as undici from 'undici';
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import * as vpa from '../../..';
import { createPacProxyAgent } from '../../../src/agent';
import { testRequest, ca, directProxyAgentParams, unusedCa, directProxyAgentParamsV1, proxiedProxyAgentParamsV1 } from './utils';

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
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(directProxyAgentParams);
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
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(directProxyAgentParams);
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
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(directProxyAgentParams);
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
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(directProxyAgentParams);
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
	it.skip('should reuse socket with agent', async function () {
		// Skipping due to https://github.com/microsoft/vscode/issues/228872.
		// https://github.com/microsoft/vscode/issues/173861
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(directProxyAgentParams);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(directProxyAgentParams, https, resolveProxy),
		} as any;
		await testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			ca,
		});
		await testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			ca,
		}, {
			assertResult: (_, req) => {
				assert.strictEqual(req.reusedSocket, true);
			}
		});
	});
	
	it('should use system certificates', async function () {
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(directProxyAgentParamsV1);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(directProxyAgentParamsV1, https, resolveProxy),
		} as any;
		await testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			_vscodeTestReplaceCaCerts: true,
		});
	});
	it('should use ca request option', async function () {
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(directProxyAgentParamsV1);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(directProxyAgentParamsV1, https, resolveProxy),
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
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(directProxyAgentParamsV1);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(directProxyAgentParamsV1, https, resolveProxy),
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
	for (const loadSystemCertificatesFromNode of [
		() => true,
		() => false,
		undefined as any as (() => boolean), // Test backward compatibility
	]) {
		it('should use ca agent option 2', async function () {
			try {
				vpa.resetCaches(); // Allows loadAdditionalCertificates to run again.
				const params = {
					...directProxyAgentParamsV1,
					loadAdditionalCertificates: async () => [
						...await vpa.loadSystemCertificates({
							loadSystemCertificatesFromNode,
							log: console,
						}),
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
	}
	it('should prefer ca agent option', async function () {
		const { resolveProxyWithRequest: resolveProxy } = vpa.createProxyResolver(directProxyAgentParamsV1);
		const patchedHttps: typeof https = {
			...https,
			...vpa.createHttpPatch(directProxyAgentParamsV1, https, resolveProxy),
		} as any;
		await testRequest(patchedHttps, {
			hostname: 'test-https-server',
			path: '/test-path',
			_vscodeTestReplaceCaCerts: true,
			ca: unusedCa,
			agent: new https.Agent({ ca: undefined }),
		});
	});

	it('should pass-through with socketPath (fetch)', async function () {
		// https://github.com/microsoft/vscode/issues/236423
		const server = http.createServer((_, res) => {
			res.writeHead(200, { 'Content-Type': 'application/json' });
			res.end(JSON.stringify({ status: 'OK from socket path!' }));
		});
		try {
			const socketPath = path.join(os.tmpdir(), `test-server-${crypto.randomUUID()}.sock`);
			await new Promise<void>(resolve => server.listen(socketPath, resolve));
	
			const { resolveProxyURL } = vpa.createProxyResolver(proxiedProxyAgentParamsV1);
			const patchedFetch = vpa.createFetchPatch(proxiedProxyAgentParamsV1, globalThis.fetch, resolveProxyURL);
			const patchedUndici = { ...undici };
			vpa.patchUndici(patchedUndici);
			const res = await patchedFetch('http://localhost/test-path', {
				dispatcher: new patchedUndici.Agent({
					connect: {
						socketPath,
					},
				})
			} as any);
			assert.strictEqual(res.status, 200);
			assert.strictEqual((await res.json()).status, 'OK from socket path!');
		} finally {
			server.close();
		}
	});
	it('should pass-through allowH2 with patched undici (fetch)', async function () {
		const { resolveProxyURL } = vpa.createProxyResolver(directProxyAgentParamsV1);
		const patchedFetch = vpa.createFetchPatch(directProxyAgentParamsV1, globalThis.fetch, resolveProxyURL);
			const patchedUndici = { ...undici };
			vpa.patchUndici(patchedUndici);
			const res = await patchedFetch('https://test-https-server/test-path', {
				dispatcher: new patchedUndici.Agent({
					allowH2: true
				})
			} as any);
		assert.strictEqual(res.status, 200);
		assert.strictEqual((await res.json()).status, 'OK HTTP2!');
	});
	it('should pass-through allowH2 with unpatched undici (fetch)', async function () {
		const { resolveProxyURL } = vpa.createProxyResolver(directProxyAgentParamsV1);
		const patchedFetch = vpa.createFetchPatch(directProxyAgentParamsV1, globalThis.fetch, resolveProxyURL);
			const res = await patchedFetch('https://test-https-server/test-path', {
				dispatcher: new undici.Agent({
					allowH2: true
				})
			} as any);
		assert.strictEqual(res.status, 200);
		assert.strictEqual((await res.json()).status, 'OK HTTP2!');
	});
});
