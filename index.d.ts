/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { Agent, ClientRequest, RequestOptions } from 'http';

export declare interface ProxyAgentOptions {
	resolveProxy(req: ClientRequest, opts: RequestOptions, url: string, callback: (proxy: string) => void): void;
	defaultPort: number;
	originalAgent?: Agent;
}

export declare class ProxyAgent extends Agent {
	constructor(options: ProxyAgentOptions)
}
