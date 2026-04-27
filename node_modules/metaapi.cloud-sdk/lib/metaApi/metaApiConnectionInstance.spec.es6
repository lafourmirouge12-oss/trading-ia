'use strict';

import MetaApiWebsocketClient from '../clients/metaApi/metaApiWebsocket.client';
import MetaApiConnectionInstance from './metaApiConnectionInstance';
import MetaApiConnection from './metaApiConnection';
import should from 'should';
import sinon from 'sinon';

/**
 * @test {MetaApiConnectionInstance}
 */
describe('MetaApiConnectionInstance', () => {

  let sandbox = sinon.createSandbox();
  let connectionInstance;
  let websocketClient;

  beforeEach(async () => {
    let connection = sandbox.createStubInstance(MetaApiConnection);
    sandbox.stub(connection, 'account').get(() => ({id: 'accountId'}));
    websocketClient = sandbox.createStubInstance(MetaApiWebsocketClient);
    connectionInstance = new MetaApiConnectionInstance(websocketClient, connection);
    await connectionInstance.connect();
  });

  afterEach(() => {
    sandbox.restore();
  });

  /**
   * @test {MetaApiConnectionInstance#refreshSymbolQuotes}
   */
  describe('refreshSymbolQuotes', () => {

    /**
     * @test {MetaApiConnectionInstance#refreshSymbolQuotes}
     */
    it('should refresh symbol quotes ', async () => {
      websocketClient.refreshSymbolQuotes.resolves({
        quotes: [{symbol: 'EURUSD'}, {symbol: 'BTCUSD'}],
        balance: 1100
      });
      should(await connectionInstance.refreshSymbolQuotes(['EURUSD', 'BTCUSD'])).deepEqual({
        quotes: [{symbol: 'EURUSD'}, {symbol: 'BTCUSD'}],
        balance: 1100
      });
      sinon.assert.calledWith(websocketClient.refreshSymbolQuotes, 'accountId', ['EURUSD', 'BTCUSD']);
    });

  });

});
