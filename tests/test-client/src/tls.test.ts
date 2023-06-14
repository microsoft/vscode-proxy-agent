import * as tls from 'tls';
import { createTlsPatch, SecureContextOptionsPatch } from '../../../src/index';
import { ca, directProxyAgentParams } from './utils';

describe('TLS patch', function () {
	it('should work without CA option v1', function (done) {
		const tlsPatched = {
			...tls,
			...createTlsPatch({
				...directProxyAgentParams,
				useSystemCertificatesV2: false,
				addCertificates: [],
			}, tls),
		};
		const options: tls.ConnectionOptions = {
			host: 'test-https-server',
			port: 443,
			servername: 'test-https-server', // for SNI
		};
		(options as SecureContextOptionsPatch)._vscodeAdditionalCaCerts = ca.map(ca => ca.toString());
		options.secureContext = tlsPatched.createSecureContext(options); // Needed here because we don't patch tls like in VS Code.
		const socket = tlsPatched.connect(options);
		socket.on('error', done);
		socket.on('secureConnect', () => {
			const { authorized, authorizationError } = socket;
			socket.destroy();
			if (authorized) {
				done();
			} else {
				done(authorizationError);
			}
		});
	});

	it('should work without CA option v2', function (done) {
		const tlsPatched = {
			...tls,
			...createTlsPatch(directProxyAgentParams, tls),
		};
		const options: tls.ConnectionOptions = {
			host: 'test-https-server',
			port: 443,
			servername: 'test-https-server', // for SNI
		};
		const socket = tlsPatched.connect(options);
		socket.on('error', done);
		socket.on('secureConnect', () => {
			const { authorized, authorizationError } = socket;
			socket.destroy();
			if (authorized) {
				done();
			} else {
				done(authorizationError);
			}
		});
	});
});
