import * as assert from 'assert';
import { createProxyAuthorizationLookup, Log, ProxyAuthorizationInfo } from '../../src/index';

const log: Log = {
	trace() { },
	debug() { },
	info() { },
	warn() { },
	error() { },
};

describe('createProxyAuthorizationLookup', function () {
	it('looks up Kerberos authorization once per connection', async function () {
		let lookupCount = 0;
		const lookup = createProxyAuthorizationLookup({
			log,
			lookupKerberosAuthorization: async proxyURL => {
				lookupCount++;
				assert.strictEqual(proxyURL, 'http://proxy.example:8080');
				return 'Negotiate token';
			},
		});
		const state = {};

		assert.strictEqual(await lookup('http://proxy.example:8080/', 'Negotiate', state), 'Negotiate token');
		assert.strictEqual(await lookup('http://proxy.example:8080/', 'Negotiate', state), undefined);
		assert.strictEqual(lookupCount, 1);
	});

	it('caches Basic credentials and retries rejected credentials', async function () {
		const authInfos: ProxyAuthorizationInfo[] = [];
		const lookup = createProxyAuthorizationLookup({
			log,
			lookupAuthorization: async authInfo => {
				authInfos.push(authInfo);
				return { username: 'user', password: `password-${authInfo.attempt}` };
			},
		});

		const firstState = {};
		assert.strictEqual(await lookup('http://proxy.example:8080/', 'Basic realm="proxy realm"', firstState), `Basic ${Buffer.from('user:password-1').toString('base64')}`);

		const secondState = {};
		assert.strictEqual(await lookup('http://proxy.example:8080', undefined, secondState), `Basic ${Buffer.from('user:password-1').toString('base64')}`);
		assert.strictEqual(await lookup('http://proxy.example:8080', 'Basic realm="proxy realm"', secondState), `Basic ${Buffer.from('user:password-1').toString('base64')}`);
		assert.strictEqual(await lookup('http://proxy.example:8080', 'Basic realm="proxy realm"', secondState), `Basic ${Buffer.from('user:password-2').toString('base64')}`);

		assert.deepStrictEqual(authInfos, [
			{ scheme: 'basic', host: 'proxy.example', port: 8080, realm: 'proxy realm', isProxy: true, attempt: 1 },
			{ scheme: 'basic', host: 'proxy.example', port: 8080, realm: 'proxy realm', isProxy: true, attempt: 1 },
			{ scheme: 'basic', host: 'proxy.example', port: 8080, realm: 'proxy realm', isProxy: true, attempt: 2 },
		]);
	});

	it('reports requested authentication types', async function () {
		const authenticationTypes: string[][] = [];
		const lookup = createProxyAuthorizationLookup({
			log,
			onDidRequestAuthentication: types => authenticationTypes.push(types),
		});

		await lookup('http://proxy.example:8080', ['Negotiate', 'Basic realm="proxy"'], {});

		assert.deepStrictEqual(authenticationTypes, [['Negotiate', 'Basic']]);
	});
});