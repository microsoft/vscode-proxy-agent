import * as assert from 'assert';
import { once } from 'events';
import * as net from 'net';
import { createFetchPatch, createProxyResolver, LogLevel, ProxyAgentParams, resetCaches } from '../../src';

function createParams(proxyURL: string, addCertificates: boolean): ProxyAgentParams {
	const noop = () => { };
	return {
		resolveProxy: async () => undefined,
		getProxyURL: () => proxyURL,
		getProxySupport: () => 'override',
		isAdditionalFetchSupportEnabled: () => true,
		isWebSocketPatchEnabled: () => true,
		addCertificatesV1: () => addCertificates,
		addCertificatesV2: () => false,
		loadSystemCertificatesFromNode: () => false,
		loadAdditionalCertificates: async () => [],
		log: { trace: noop, debug: noop, info: noop, warn: noop, error: noop },
		getLogLevel: () => LogLevel.Off,
		proxyResolveTelemetry: noop,
		isUseHostProxyEnabled: () => true,
		env: {},
	};
}

async function readBytes(socket: net.Socket, length: number): Promise<Buffer> {
	let data: Buffer | null;
	while ((data = socket.read(length)) === null) {
		if (socket.destroyed || socket.readableEnded) {
			throw new Error('SOCKS client disconnected');
		}
		await once(socket, 'readable');
	}
	return data;
}

async function serveSocksRequest(socket: net.Socket): Promise<void> {
	// A plain SOCKS proxy must receive a SOCKS greeting, not a TLS ClientHello.
	assert.deepStrictEqual(await readBytes(socket, 2), Buffer.from([5, 1]));
	assert.deepStrictEqual(await readBytes(socket, 1), Buffer.from([0]));
	socket.write(Buffer.from([5, 0]));

	assert.deepStrictEqual(await readBytes(socket, 4), Buffer.from([5, 1, 0, 3]));
	const hostLength = (await readBytes(socket, 1))[0];
	assert.strictEqual((await readBytes(socket, hostLength)).toString(), 'example.test');
	assert.strictEqual((await readBytes(socket, 2)).readUInt16BE(), 80);
	socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 80]));

	// Serve a response inside the tunnel without depending on an external server.
	let request = '';
	while (!request.endsWith('\r\n\r\n')) {
		request += (await readBytes(socket, 1)).toString();
	}
	assert.ok(request.startsWith('GET /test-path HTTP/1.1\r\n'));
	socket.end('HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nproxied');
}

describe('fetch through a SOCKS proxy', function () {
	for (const addCertificates of [false, true]) {
		it(`uses a plain SOCKS5 tunnel with additional certificates ${addCertificates ? 'enabled' : 'disabled'}`, async function () {
			const sockets = new Set<net.Socket>();
			const errors: unknown[] = [];
			const proxy = net.createServer(socket => {
				sockets.add(socket);
				socket.on('close', () => sockets.delete(socket));
				void serveSocksRequest(socket).catch(error => {
					errors.push(error);
					socket.destroy();
				});
			});
			proxy.listen(0, '127.0.0.1');
			await once(proxy, 'listening');
			try {
				const { port } = proxy.address() as net.AddressInfo;
				const params = createParams(`socks5://127.0.0.1:${port}`, addCertificates);
				const { resolveProxyURL } = createProxyResolver(params);
				const patchedFetch = createFetchPatch(params, globalThis.fetch, resolveProxyURL);
				const response = await patchedFetch('http://example.test/test-path', { signal: AbortSignal.timeout(1000) });
				assert.strictEqual(response.status, 200);
				assert.strictEqual(await response.text(), 'proxied');
				assert.deepStrictEqual(errors, []);
			} finally {
				for (const socket of sockets) {
					socket.destroy();
				}
				await new Promise<void>(resolve => proxy.close(() => resolve()));
				resetCaches();
			}
		});
	}
});
