import * as assert from 'assert';
import { WebSocket } from 'undici';
import * as vpa from '../../..';
import { directProxyAgentParams } from './utils';

function connectWebSocket(PatchedWebSocket: typeof globalThis.WebSocket, url: string, message: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const ws = new PatchedWebSocket(url);
		ws.onopen = () => {
			ws.send(message);
		};
		ws.onmessage = async (event) => {
			ws.close();
			const data = typeof event.data === 'string' ? event.data : await (event.data as Blob).text();
			resolve(data);
		};
		ws.onerror = (event) => {
			reject(new Error(`WebSocket error: ${event}`));
		};
		ws.onclose = (event) => {
			if (!event.wasClean && event.code !== 1000) {
				reject(new Error(`WebSocket closed with code ${event.code}: ${event.reason}`));
			}
		};
	});
}

describe('WebSocket proxied', function () {
	it('should use HTTP proxy for WSS connection', async function () {
		const params: vpa.ProxyAgentParams = {
			...directProxyAgentParams,
			resolveProxy: async () => 'PROXY test-http-proxy:3128',
		};
		const { resolveProxyURL } = vpa.createProxyResolver(params);
		const PatchedWebSocket = vpa.createWebSocketPatch(params, WebSocket as any, resolveProxyURL);
		const result = await connectWebSocket(PatchedWebSocket, 'wss://test-wss-server', 'hello proxy');
		assert.strictEqual(result, 'hello proxy');
	});

	it('should use HTTP proxy with basic auth for WSS connection', async function () {
		const params: vpa.ProxyAgentParams = {
			...directProxyAgentParams,
			resolveProxy: async () => 'PROXY foo:bar@test-http-auth-proxy:3128',
		};
		const { resolveProxyURL } = vpa.createProxyResolver(params);
		const PatchedWebSocket = vpa.createWebSocketPatch(params, WebSocket as any, resolveProxyURL);
		const result = await connectWebSocket(PatchedWebSocket, 'wss://test-wss-server', 'hello auth');
		assert.strictEqual(result, 'hello auth');
	});

	it('should call auth callback after 407', async function () {
		const params: vpa.ProxyAgentParams = {
			...directProxyAgentParams,
			resolveProxy: async () => 'PROXY test-http-auth-proxy:3128',
			async lookupProxyAuthorization(proxyURL, proxyAuthenticate) {
				if (!proxyAuthenticate) {
					return;
				}
				assert.strictEqual(proxyAuthenticate, 'Basic realm="Squid Basic Authentication"');
				return `Basic ${Buffer.from('foo:bar').toString('base64')}`;
			},
		};
		const { resolveProxyURL } = vpa.createProxyResolver(params);
		const PatchedWebSocket = vpa.createWebSocketPatch(params, WebSocket as any, resolveProxyURL);
		const result = await connectWebSocket(PatchedWebSocket, 'wss://test-wss-server', 'hello 407');
		assert.strictEqual(result, 'hello 407');
	});

	it('should call auth callback before request', async function () {
		const params: vpa.ProxyAgentParams = {
			...directProxyAgentParams,
			resolveProxy: async () => 'PROXY test-http-auth-proxy:3128',
			async lookupProxyAuthorization(proxyURL, proxyAuthenticate) {
				assert.strictEqual(proxyAuthenticate, undefined);
				return `Basic ${Buffer.from('foo:bar').toString('base64')}`;
			},
		};
		const { resolveProxyURL } = vpa.createProxyResolver(params);
		const PatchedWebSocket = vpa.createWebSocketPatch(params, WebSocket as any, resolveProxyURL);
		const result = await connectWebSocket(PatchedWebSocket, 'wss://test-wss-server', 'hello preauth');
		assert.strictEqual(result, 'hello preauth');
	});

	it('should use HTTPS proxy for WSS connection', async function () {
		const params: vpa.ProxyAgentParams = {
			...directProxyAgentParams,
			resolveProxy: async () => 'HTTPS test-https-proxy:8080',
		};
		const { resolveProxyURL } = vpa.createProxyResolver(params);
		const PatchedWebSocket = vpa.createWebSocketPatch(params, WebSocket as any, resolveProxyURL);
		const result = await connectWebSocket(PatchedWebSocket, 'wss://test-wss-server', 'hello tls proxy');
		assert.strictEqual(result, 'hello tls proxy');
	});

	it('should capture response headers', async function () {
		const params: vpa.ProxyAgentParams = {
			...directProxyAgentParams,
			resolveProxy: async () => 'PROXY test-http-proxy:3128',
		};
		const { resolveProxyURL } = vpa.createProxyResolver(params);
		const PatchedWebSocket = vpa.createWebSocketPatch(params, WebSocket as any, resolveProxyURL);
		const ws = new PatchedWebSocket('wss://test-wss-server');
		await new Promise<void>((resolve, reject) => {
			ws.onopen = () => {
				ws.close();
				const headers = (ws as any).responseHeaders;
				assert.ok(headers, 'responseHeaders should be defined');
				assert.strictEqual(typeof headers, 'object');
				assert.ok(headers['upgrade'] || headers['connection'], 'should have upgrade response headers');
				assert.strictEqual((ws as any).responseStatusCode, 101, 'should have 101 status code');
				resolve();
			};
			ws.onerror = (event) => {
				reject(new Error(`WebSocket error: ${event}`));
			};
		});
	});

	it('should capture response headers on a 404 response', async function () {
		const params: vpa.ProxyAgentParams = {
			...directProxyAgentParams,
			resolveProxy: async () => 'PROXY test-http-proxy:3128',
		};
		const { resolveProxyURL } = vpa.createProxyResolver(params);
		const PatchedWebSocket = vpa.createWebSocketPatch(params, WebSocket as any, resolveProxyURL);
		const ws = new PatchedWebSocket('wss://test-https-server');
		await new Promise<void>((resolve, reject) => {
			ws.onopen = () => {
				ws.close();
				reject(new Error('WebSocket should not have connected'));
			};
			ws.onerror = () => {
				const headers = (ws as any).responseHeaders;
				assert.ok(headers, 'responseHeaders should be defined on error');
				assert.strictEqual(typeof headers, 'object');
				assert.ok(headers['content-type'], 'should have content-type header');
				assert.strictEqual((ws as any).responseStatusCode, 404, 'should have 404 status code');
				assert.strictEqual((ws as any).responseStatusText, 'Not Found', 'should have status message');
				resolve();
			};
		});
	});

	it('should capture response headers on 407 proxy response', async function () {
		const params: vpa.ProxyAgentParams = {
			...directProxyAgentParams,
			resolveProxy: async () => 'PROXY test-http-auth-proxy:3128',
		};
		const { resolveProxyURL } = vpa.createProxyResolver(params);
		const PatchedWebSocket = vpa.createWebSocketPatch(params, WebSocket as any, resolveProxyURL);
		const ws = new PatchedWebSocket('wss://test-wss-server');
		await new Promise<void>((resolve, reject) => {
			ws.onopen = () => {
				ws.close();
				reject(new Error('WebSocket should not have connected'));
			};
			ws.onerror = () => {
				const headers = (ws as any).responseHeaders;
				assert.ok(headers, 'responseHeaders should be defined on 407');
				assert.strictEqual(typeof headers, 'object');
				assert.ok(headers['proxy-authenticate'], 'should have proxy-authenticate header');
				assert.strictEqual((ws as any).responseStatusCode, 407, 'should have 407 status code');
				resolve();
			};
		});
	});

	it('should capture networkError on HTTP proxy connection refused', async function () {
		const params: vpa.ProxyAgentParams = {
			...directProxyAgentParams,
			resolveProxy: async () => 'PROXY 127.0.0.1:1',
		};
		const { resolveProxyURL } = vpa.createProxyResolver(params);
		const PatchedWebSocket = vpa.createWebSocketPatch(params, WebSocket as any, resolveProxyURL);
		const ws = new PatchedWebSocket('wss://test-wss-server');
		await new Promise<void>((resolve, reject) => {
			ws.onopen = () => {
				ws.close();
				reject(new Error('WebSocket should not have connected'));
			};
			ws.onerror = () => {
				const networkError: Error | undefined = (ws as any).networkError;
				assert.ok(networkError, 'networkError should be defined');
				assert.ok(networkError instanceof Error, 'networkError should be an Error');
				resolve();
			};
		});
	});

	it('should capture networkError on HTTPS proxy connection refused', async function () {
		const params: vpa.ProxyAgentParams = {
			...directProxyAgentParams,
			resolveProxy: async () => 'HTTPS 127.0.0.1:1',
		};
		const { resolveProxyURL } = vpa.createProxyResolver(params);
		const PatchedWebSocket = vpa.createWebSocketPatch(params, WebSocket as any, resolveProxyURL);
		const ws = new PatchedWebSocket('wss://test-wss-server');
		await new Promise<void>((resolve, reject) => {
			ws.onopen = () => {
				ws.close();
				reject(new Error('WebSocket should not have connected'));
			};
			ws.onerror = () => {
				const networkError: Error | undefined = (ws as any).networkError;
				assert.ok(networkError, 'networkError should be defined');
				assert.ok(networkError instanceof Error, 'networkError should be an Error');
				resolve();
			};
		});
	});
});
