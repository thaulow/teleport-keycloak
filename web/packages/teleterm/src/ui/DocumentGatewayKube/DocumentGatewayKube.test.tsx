/**
 * Teleport
 * Copyright (C) 2025 Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
import 'jest-canvas-mock';

import userEvent from '@testing-library/user-event';

import { render, screen } from 'design/utils/testing';

import Logger, { NullService } from 'teleterm/logger';
import { MockedUnaryCall } from 'teleterm/services/tshd/cloneableClient';
import {
  makeKubeGateway,
  makeRootCluster,
} from 'teleterm/services/tshd/testHelpers';
import { MockAppContextProvider } from 'teleterm/ui/fixtures/MockAppContextProvider';
import { MockAppContext } from 'teleterm/ui/fixtures/mocks';
import type * as docs from 'teleterm/ui/services/workspacesService';
import { KubeUri, routing } from 'teleterm/ui/uri';

import { MockWorkspaceContextProvider } from '../fixtures/MockWorkspaceContextProvider';
import { DocumentGatewayKube } from './DocumentGatewayKube';

beforeAll(() => {
  Logger.init(new NullService());
});

test('it allows reconnecting when the gateway fails to be created', async () => {
  const user = userEvent.setup();

  const appContext = new MockAppContext();
  const cluster = makeRootCluster();
  const gateway = makeKubeGateway();
  const doc: docs.DocumentGatewayKube = {
    uri: '/docs/1',
    kind: 'doc.gateway_kube',
    targetUri: gateway.targetUri as KubeUri,
    rootClusterId: routing.parseClusterUri(cluster.uri).params['rootClusterId'],
    leafClusterId: undefined,
    origin: 'resource_table',
    title: '',
    status: '',
  };
  appContext.addRootClusterWithDoc(cluster, doc);

  jest
    .spyOn(appContext.tshd, 'createGateway')
    .mockReturnValueOnce(
      new MockedUnaryCall(undefined, new Error('Something went wrong'))
    )
    .mockReturnValueOnce(new MockedUnaryCall(gateway));

  render(
    <MockAppContextProvider appContext={appContext}>
      <MockWorkspaceContextProvider>
        <DocumentGatewayKube visible doc={doc} />
      </MockWorkspaceContextProvider>
    </MockAppContextProvider>
  );

  expect(
    await screen.findByText('Could not establish the connection')
  ).toBeInTheDocument();

  await user.click(screen.getByText('Reconnect'));

  // Verify that the gateway was created by checking if the terminal was rendered.
  // "Terminal input" is an ARIA label added by xterm.js.
  expect(await screen.findByLabelText('Terminal input')).toBeInTheDocument();
});
