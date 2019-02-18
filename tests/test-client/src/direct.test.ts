import * as https from 'https';
import { ClientRequest, RequestOptions } from 'http';
import * as vpa from '../../..';
import { testRequest, ca } from './utils';

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
});
