import * as net from 'net';
import * as tls from 'tls';
import * as dns from 'dns';
import { createNetPatch, createTlsPatch, toLogString } from '../../../src/index';
import { directProxyAgentParams } from './utils';
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
Connection: close

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
Connection: close

`);
		const response = await p;
		assert.ok(response.startsWith('HTTP/1.1 200 OK'), `Unexpected response: ${response}`);
	});

	it('net.connect() should support timeout', async () => {
		const netPatched = {
			...net,
			...createNetPatch(directProxyAgentParams, net),
		};
		const socket = netPatched.connect({
			host: 'test-https-server',
			port: 808,
			timeout: 500,
		});
		const timeout = new Promise((resolve, reject) => {
			socket.on('timeout', resolve);
			socket.on('error', reject);
			socket.on('end', reject);
		});
		await Promise.race([timeout, new Promise((_, reject) => setTimeout(() => reject(new Error('no timeout event received')), 1000))]);
	});

	it('tls.connect() should support timeout', async () => {
		const tlsPatched = {
			...tls,
			...createTlsPatch(directProxyAgentParams, tls),
		};
		const socket = tlsPatched.connect({
			host: 'test-https-server',
			port: 443,
			servername: 'test-https-server', // for SNI
			timeout: 500,
		});
		const timeout = new Promise((resolve, reject) => {
			socket.on('timeout', resolve);
			socket.on('error', reject);
			socket.on('end', reject);
		});
		await Promise.race([timeout, new Promise((_, reject) => setTimeout(() => reject(new Error('no timeout event received')), 1000))]);
	});

	it('tls.connect() should support net.connect() options', async () => {
		const tlsPatched = {
			...tls,
			...createTlsPatch(directProxyAgentParams, tls),
		};
		let lookupUsed = false;
		const socket = tlsPatched.connect(443, 'test-https-server', {
			servername: 'test-https-server', // for SNI
			lookup: (hostname, options, callback) => {
				lookupUsed = true;
				dns.lookup(hostname, options, callback);
			},
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
Connection: close

`);
		const response = await p;
		assert.ok(response.startsWith('HTTP/1.1 200 OK'), `Unexpected response: ${response}`);
		assert.ok(lookupUsed, 'lookup() was not used');
	});

	it('toLogString() should work', async () => {
		assert.strictEqual(toLogString([{
			str: 'string',
			buf: Buffer.from('buffer'),
			obj: { a: 1 },
			arr: [1, 2, 3],
			undef: undefined,
			null: null,
			bool: true,
			num: 1,
			sym: Symbol('test'),
			fn: () => {},
			date: new Date(0),
			obj2: Object.create(null),
		}, () => {}]), '[{"str":"string","buf":"[object Object]","obj":"[object Object]","arr":"1,2,3","null":"null","bool":true,"num":1,"fn":"[Function: fn]","date":"1970-01-01T00:00:00.000Z","obj2":"[object Object]"}, "[Function: ]"]');
	});
});
