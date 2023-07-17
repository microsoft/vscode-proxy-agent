import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';
import * as assert from 'assert';

import * as vpa from '../../..';

export const ca = [
	fs.readFileSync(path.join(__dirname, '../../test-https-server/ssl_cert.pem')),
	fs.readFileSync(path.join(__dirname, '../../test-https-server/ssl_teapot_cert.pem')),
];

export const directProxyAgentParams: vpa.ProxyAgentParams = {
	resolveProxy: async () => 'DIRECT',
    getProxyURL: () => undefined,
    getProxySupport: () => 'override',
    getSystemCertificatesV1: () => false,
    getSystemCertificatesV2: () => true,
	log: (_level: vpa.LogLevel, message: string, ...args: any[]) => console.log(message, ...args),
	getLogLevel: () => vpa.LogLevel.Debug,
	proxyResolveTelemetry: () => undefined,
	useHostProxy: true,
	addCertificates: ca,
	env: {},
};

export async function testRequest<C extends typeof https | typeof http>(client: C, options: C extends typeof https ? https.RequestOptions : http.RequestOptions, testOptions: { assertResult?: (result: any) => void; } = {}) {
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
						testOptions.assertResult(result);
					}
					resolve();
				} catch (err: any) {
					err.message = `${err.message}: ${data}`;
					reject(err);
				}
			});
		});
		req.on('error', err => {
			reject(new Error(`Error: ${err.message}`));
		});
		req.end();
	});
}
