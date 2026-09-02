/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as tls from 'tls';
import { parentPort } from 'worker_threads';

if (!parentPort) {
	throw new Error('System certificate worker must run in a worker thread');
}

parentPort.postMessage(tls.getCACertificates('system'));
