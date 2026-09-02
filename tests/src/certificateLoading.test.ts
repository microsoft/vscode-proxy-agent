import * as assert from 'assert';
import { getOrLoadAdditionalCertificates, LogLevel, ProxyAgentParams, resetCaches } from '../../src';

function createParams(loadAdditionalCertificates: () => Promise<string[]>): ProxyAgentParams {
	const noop = () => { };
	return {
		resolveProxy: async () => undefined,
		getProxyURL: () => undefined,
		getProxySupport: () => 'override',
		isAdditionalFetchSupportEnabled: () => true,
		isWebSocketPatchEnabled: () => true,
		addCertificatesV1: () => true,
		addCertificatesV2: () => false,
		loadSystemCertificatesFromNode: () => true,
		loadAdditionalCertificates,
		log: { trace: noop, debug: noop, info: noop, warn: noop, error: noop },
		getLogLevel: () => LogLevel.Off,
		proxyResolveTelemetry: noop,
		isUseHostProxyEnabled: () => true,
		env: {},
	};
}

describe('certificate loading', function () {
	afterEach(() => resetCaches());

	it('retries loading additional certificates after a failure', async function () {
		let attempts = 0;
		const params = createParams(async () => {
			if (++attempts === 1) {
				throw new Error('Certificate loading failed');
			}
			return ['certificate'];
		});

		await assert.rejects(getOrLoadAdditionalCertificates(params), /Certificate loading failed/);
		assert.deepStrictEqual(await getOrLoadAdditionalCertificates(params), ['certificate']);
	});
});
