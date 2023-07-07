import * as net from 'net';
import * as tls from 'tls';
import { createNetPatch, createTlsPatch, resetCaches, SecureContextOptionsPatch } from '../../../src/index';
import { testRequest, ca, directProxyAgentParams } from './utils';
import * as assert from 'assert';

describe('Socket client', function () {
	it('net.connect() should work without delay', async () => {
		const netPatched = {
			...net,
			...createNetPatch(directProxyAgentParams, net),
		};
		const socket = netPatched.connect(808, 'test-https-server');
		const p = new Promise<string>((resolve, reject) => {
			socket.on('error', reject);
			const chunks: Buffer[] = [];
			socket.on('data', chunk => chunks.push(chunk));
			socket.on('end', () => {
				resolve(Buffer.concat(chunks).toString());
			});
		});
		socket.write(`GET /test-path-unencrypted HTTP/1.1
Host: test-http-server

`);
		const response = await p;
		assert.ok(response.startsWith('HTTP/1.1 200 OK'), `Unexpected response: ${response}`);
	});

	it('tls.connect() should work without delay', async () => {
		const tlsPatched = {
			...tls,
			...createTlsPatch(directProxyAgentParams, tls),
		};
		const socket = tlsPatched.connect({
			host: 'test-https-server',
			port: 443,
			servername: 'test-https-server', // for SNI
		});
		const p = new Promise<string>((resolve, reject) => {
			socket.on('error', reject);
			const chunks: Buffer[] = [];
			socket.on('data', chunk => chunks.push(chunk));
			socket.on('end', () => {
				resolve(Buffer.concat(chunks).toString());
			});
		});
		socket.write(`GET /test-path HTTP/1.1
Host: test-https-server

`);
		const response = await p;
		assert.ok(response.startsWith('HTTP/1.1 200 OK'), `Unexpected response: ${response}`);
	});
});
