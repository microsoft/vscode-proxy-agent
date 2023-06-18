import * as net from 'net';
import * as tls from 'tls';
import { createNetPatch, createTlsPatch, resetCaches, SecureContextOptionsPatch } from '../../../src/index';
import { ca, directProxyAgentParams } from './utils';

describe('TLS patch', function () {
	beforeEach(() => {
		resetCaches();
	});
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

	it('should work with existing connected socket v2', function (done) {
		const netPatched = {
			...net,
			...createNetPatch(directProxyAgentParams, net),
		};
		const tlsPatched = {
			...tls,
			...createTlsPatch(directProxyAgentParams, tls),
		};
		const existingSocket = netPatched.connect(443, 'test-https-server');
		existingSocket.on('connect', () => {
			const options: tls.ConnectionOptions = {
				socket: existingSocket,
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

	it('should work with existing connecting socket v2', function (done) {
		const netPatched = {
			...net,
			...createNetPatch(directProxyAgentParams, net),
		};
		const tlsPatched = {
			...tls,
			...createTlsPatch(directProxyAgentParams, tls),
		};
		const existingSocket = netPatched.connect(443, 'test-https-server');
		const options: tls.ConnectionOptions = {
			socket: existingSocket,
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
