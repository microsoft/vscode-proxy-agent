import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';
import * as assert from 'assert';

import * as vpa from '../../..';
import { loadSystemCertificates } from '../../../src';

export const ca = [
	fs.readFileSync(path.join(__dirname, '../../test-https-server/ssl_cert.pem')).toString(),
	fs.readFileSync(path.join(__dirname, '../../test-https-server/ssl_teapot_cert.pem')).toString(),
];

export const unusedCa = fs.readFileSync(path.join(__dirname, '../../test-https-server/ssl_unused_cert.pem')).toString();

export const directProxyAgentParams: vpa.ProxyAgentParams = {
	resolveProxy: async () => 'DIRECT',
	getProxyURL: () => undefined,
	getProxySupport: () => 'override',
	addCertificatesV1: () => false,
	addCertificatesV2: () => true,
	log: console,
	getLogLevel: () => vpa.LogLevel.Trace,
	proxyResolveTelemetry: () => undefined,
	useHostProxy: true,
	loadAdditionalCertificates: async () => [
		...await loadSystemCertificates({ log: console }),
		...ca,
	],
	env: {},
};

export const directProxyAgentParamsV1: vpa.ProxyAgentParams = {
	...directProxyAgentParams,
	addCertificatesV1: () => true,
	addCertificatesV2: () => false,
};

export const proxiedProxyAgentParamsV1: vpa.ProxyAgentParams = {
	...directProxyAgentParamsV1,
	resolveProxy: async () => 'PROXY test-http-proxy:3128',
};

export async function testRequest<C extends typeof https | typeof http>(client: C, options: C extends typeof https ? (https.RequestOptions & vpa.SecureContextOptionsPatch) : http.RequestOptions, testOptions: { assertResult?: (result: any, req: http.ClientRequest, res: http.IncomingMessage) => void; } = {}) {
	return new Promise<void>((resolve, reject) => {
		const req = client.request(options, res => {
			if (!res.statusCode || res.statusCode < 200 || res.statusCode > 299) {
				const chunks: Buffer[] = [];
				res.on('data', chunk => chunks.push(chunk));
				res.on('end', () => {
					const err = new Error(`Error status: ${res.statusCode} ${res.statusMessage} \n${Buffer.concat(chunks).toString()}`);
					(err as any).statusCode = res.statusCode;
					(err as any).statusMessage = res.statusMessage;
					reject(err);
				});
				return;
			}
			let data = '';
			res.setEncoding('utf8');
			res.on('data', chunk => {
				data += chunk;
			});
			res.on('end', () => {
				try {
					const result = JSON.parse(data);
					assert.equal(result.status, 'OK!');
					if (testOptions.assertResult) {
						testOptions.assertResult(result, req, res);
					}
					resolve();
				} catch (err: any) {
					err.message = `${err.message}: ${data}`;
					reject(err);
				}
			});
		});
		req.on('error', err => {
			reject(err);
		});
		req.end();
	});
}
