import * as undici from 'undici';
import * as assert from 'assert';
import { setProxyAuthorizationHeader } from '../../src/index';

describe('setProxyAuthorizationHeader', function () {
	it('should create flat array when no headers exist', function () {
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET' };
		setProxyAuthorizationHeader(options, 'Basic abc123');
		assert.deepStrictEqual(options.headers, ['Proxy-Authorization', 'Basic abc123']);
	});

	it('should add to flat array headers', function () {
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET', headers: ['Content-Type', 'application/json'] };
		setProxyAuthorizationHeader(options, 'Basic abc123');
		assert.deepStrictEqual(options.headers, ['Content-Type', 'application/json', 'Proxy-Authorization', 'Basic abc123']);
	});

	it('should replace existing in flat array headers', function () {
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET', headers: ['Proxy-Authorization', 'Basic old', 'Content-Type', 'application/json'] };
		setProxyAuthorizationHeader(options, 'Basic new');
		assert.deepStrictEqual(options.headers, ['Proxy-Authorization', 'Basic new', 'Content-Type', 'application/json']);
	});

	it('should add to Map headers', function () {
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET', headers: new Map([['Content-Type', 'application/json']]) };
		setProxyAuthorizationHeader(options, 'Basic abc123');
		assert.deepStrictEqual(options.headers, [['Content-Type', 'application/json'], ['Proxy-Authorization', 'Basic abc123']]);
	});

	it('should replace existing in Map headers', function () {
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET', headers: new Map([['Proxy-Authorization', 'Basic old'], ['Content-Type', 'application/json']]) };
		setProxyAuthorizationHeader(options, 'Basic new');
		assert.deepStrictEqual(options.headers, [['Proxy-Authorization', 'Basic new'], ['Content-Type', 'application/json']]);
	});

	it('should add to record headers', function () {
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET', headers: { 'Content-Type': 'application/json' } };
		setProxyAuthorizationHeader(options, 'Basic abc123');
		assert.deepStrictEqual(options.headers, { 'Content-Type': 'application/json', 'Proxy-Authorization': 'Basic abc123' });
	});

	it('should replace existing in record headers', function () {
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET', headers: { 'Proxy-Authorization': 'Basic old', 'Content-Type': 'application/json' } };
		setProxyAuthorizationHeader(options, 'Basic new');
		assert.deepStrictEqual(options.headers, { 'Proxy-Authorization': 'Basic new', 'Content-Type': 'application/json' });
	});

	it('should handle case-insensitive header name in flat array', function () {
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET', headers: ['proxy-authorization', 'Basic old'] };
		setProxyAuthorizationHeader(options, 'Basic new');
		assert.deepStrictEqual(options.headers, ['proxy-authorization', 'Basic new']);
	});

	it('should handle case-insensitive header name in Map', function () {
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET', headers: new Map([['proxy-authorization', 'Basic old']]) };
		setProxyAuthorizationHeader(options, 'Basic new');
		assert.deepStrictEqual(options.headers, [['proxy-authorization', 'Basic new']]);
	});

	it('should add to tuple array headers', function () {
		const headers: [string, string][] = [['Content-Type', 'application/json']];
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET', headers };
		setProxyAuthorizationHeader(options, 'Basic abc123');
		assert.deepStrictEqual(options.headers, [['Content-Type', 'application/json'], ['Proxy-Authorization', 'Basic abc123']]);
	});

	it('should replace existing in tuple array headers', function () {
		const headers: [string, string][] = [['Proxy-Authorization', 'Basic old'], ['Content-Type', 'application/json']];
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET', headers };
		setProxyAuthorizationHeader(options, 'Basic new');
		assert.deepStrictEqual(options.headers, [['Proxy-Authorization', 'Basic new'], ['Content-Type', 'application/json']]);
	});

	it('should handle case-insensitive header name in tuple array', function () {
		const headers: [string, string][] = [['proxy-authorization', 'Basic old']];
		const options: undici.Dispatcher.DispatchOptions = { path: '/', method: 'GET', headers };
		setProxyAuthorizationHeader(options, 'Basic new');
		assert.deepStrictEqual(options.headers, [['proxy-authorization', 'Basic new']]);
	});
});
