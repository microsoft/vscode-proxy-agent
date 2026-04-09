import * as assert from 'assert';
import { sanitizeProxyResultCredentials } from '../../src/agent';

describe('sanitizeProxyResultCredentials', function () {
	it('should replace user:pass with placeholder in PROXY target', function () {
		assert.strictEqual(
			sanitizeProxyResultCredentials('PROXY testuser:testpass@host:8080'),
			'PROXY <credentials>@host:8080'
		);
	});

	it('should replace user:pass with special chars', function () {
		assert.strictEqual(
			sanitizeProxyResultCredentials('PROXY jane.fictional%40corp.example.com:fictional123@proxy.fictional.example.com:8080'),
			'PROXY <credentials>@proxy.fictional.example.com:8080'
		);
	});

	it('should replace user-only (no password) with placeholder', function () {
		assert.strictEqual(
			sanitizeProxyResultCredentials('PROXY fictional-user@proxy.fictional.example.com:3128'),
			'PROXY <credentials>@proxy.fictional.example.com:3128'
		);
	});

	it('should replace credentials from HTTPS proxy', function () {
		assert.strictEqual(
			sanitizeProxyResultCredentials('HTTPS fictional-user:fictional-pass@proxy.fictional.example.com:8443'),
			'HTTPS <credentials>@proxy.fictional.example.com:8443'
		);
	});

	it('should not modify PROXY without credentials', function () {
		assert.strictEqual(
			sanitizeProxyResultCredentials('PROXY proxy.fictional.example.com:8080'),
			'PROXY proxy.fictional.example.com:8080'
		);
	});

	it('should not modify DIRECT', function () {
		assert.strictEqual(
			sanitizeProxyResultCredentials('DIRECT'),
			'DIRECT'
		);
	});

	it('should handle undefined', function () {
		assert.strictEqual(sanitizeProxyResultCredentials(undefined), '');
	});

	it('should handle multiple proxies with semicolons', function () {
		assert.strictEqual(
			sanitizeProxyResultCredentials('PROXY testuser:testpass@host1:8080; PROXY host2:8080; DIRECT'),
			'PROXY <credentials>@host1:8080; PROXY host2:8080; DIRECT'
		);
	});
});
