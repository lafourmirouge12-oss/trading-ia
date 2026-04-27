'use strict';

import sinon from 'sinon';
import TokenManagementApi from './tokenManagementApi';

/**
 * @test {TokenManagementApi}
 */
describe('TokenManagementApi', () => {

  let sandbox;
  let api;
  let client = {
    getAccessRules: () => {},
    narrowDownToken: () => {}
  };

  before(() => {
    api = new TokenManagementApi(client);
    sandbox = sinon.createSandbox();
  });

  afterEach(() => {
    sandbox.restore();
  });

  /**
   * @test {TokenManagementApi#getAccessRules}
   */
  it('should retrieve access rules manifest', async () => {
    let expected = [{ 
      id: 'trading-account-management-api',
      description: 'Trading account management API',
      application: 'trading-account-management-api',
      services: [{ description: 'REST API', service: 'rest' }],
      methodGroups: [{ description: 'All method groups', group: '*', 
        methods: [{description: 'All methods', method: '*'}]
      }],
      roles: [{ description: 'Read-only access to resources', roles: ['reader'] }],
      entities: [{ description: 'All entities', entity: '*' }]
    }];
    sandbox.stub(client, 'getAccessRules').resolves(expected);
    let manifest = await api.getAccessRules();
    manifest.should.equal(expected);
    sandbox.assert.calledOnce(client.getAccessRules);
  });

  /**
   * @test {TokenManagementApi#narrowDownToken}
   */
  it('should narrow down token', async () => {
    const payload = {
      accessRules: [{
        id: 'trading-account-management-api',
        application: 'trading-account-management-api',
        service: 'rest',
        resources: [{entity: 'account', id: 'accountId'}],
        methodGroups: [{group: 'account-management', methods: [{method: 'getAccount'}]}],
        roles: ['reader'],
      }]
    };
    let expected = {token: 'token'};
    sandbox.stub(client, 'narrowDownToken').resolves(expected);
    let token = await api.narrowDownToken(payload);
    token.should.equal(expected.token);
    sandbox.assert.calledOnceWithExactly(client.narrowDownToken, payload, undefined);
  });

  /**
   * @test {TokenManagementApi#narrowDownToken}
   */
  it('should narrow down token to speciffic applications, roles and resources with validity', async () => {
    const payload = {
      applications: ['trading-account-management-api'],
      roles: ['reader'],
      resources: [{entity: 'account', id: 'accountId'}]
    };
    const validityInHours = 12;
    let expected = {token: 'token'};
    sandbox.stub(client, 'narrowDownToken').resolves(expected);
    let token = await api.narrowDownToken(payload, validityInHours);
    token.should.equal(expected.token);
    sandbox.assert.calledOnceWithExactly(client.narrowDownToken, payload, validityInHours);
  });

  /**
   * @test {TokenManagementApi#narrowDownTokenApplications}
   */
  it('should narrow down token applications', async () => {
    const applications = ['trading-account-management-api', 'metastats-api'];
    const validityInHours = 3;
    let expected = {token: 'token'};
    sandbox.stub(client, 'narrowDownToken').resolves(expected);
    let token = await api.narrowDownTokenApplications(applications, validityInHours);
    token.should.equal(expected.token);
    sandbox.assert.calledOnceWithExactly(client.narrowDownToken, {applications}, validityInHours);
  });

  /**
   * @test {TokenManagementApi#narrowDownTokenRoles}
   */
  it('should narrow down token roles', async () => {
    const roles = ['reader'];
    const validityInHours = 10;
    let expected = {token: 'token'};
    sandbox.stub(client, 'narrowDownToken').resolves(expected);
    let token = await api.narrowDownTokenRoles(roles, validityInHours);
    token.should.equal(expected.token);
    sandbox.assert.calledOnceWithExactly(client.narrowDownToken, {roles}, validityInHours);
  });

  /**
   * @test {TokenManagementApi#narrowDownTokenResources}
   */
  it('should narrow down token resources', async () => {
    const resources = [{entity: 'account', id: 'accountId'}];
    const validityInHours = 12;
    let expected = {token: 'token'};
    sandbox.stub(client, 'narrowDownToken').resolves(expected);
    let token = await api.narrowDownTokenResources(resources, validityInHours);
    token.should.equal(expected.token);
    sandbox.assert.calledOnceWithExactly(client.narrowDownToken, {resources}, validityInHours);
  });

  /**
   * @test {TokenManagementApi#areTokenResourcesNarrowedDown}
   */
  it('should check and return true when token resources are narrowed down', async () => {
    const payload = {
      accessRules: [{
        methods: ['trading-account-management-api:rest:public:*:*'], 
        roles: ['reader'], 
        resources: ['account:$USER_ID$:*']
      },
      {
        methods: ['metaapi-api:rest:public:*:*'], 
        roles: ['reader'],
        resources: ['account:$USER_ID$:*', 'tracker:$USER_ID$:id123']
      }]
    };
    const token = '.' + Buffer.from(JSON.stringify(payload)).toString('base64') + '.';
    const areResourcesNarrowedDown = api.areTokenResourcesNarrowedDown(token);
    areResourcesNarrowedDown.should.be.true();
  });

  /**
   * @test {TokenManagementApi#areTokenResourcesNarrowedDown}
   */
  it('should check and return false when token resources are not narrowed down', async () => {
    const payload = {
      accessRules: [{
        methods: ['trading-account-management-api:rest:public:*:*'], 
        roles: ['reader'], 
        resources: ['*:$USER_ID$:*']
      },
      {
        methods: ['metaapi-api:rest:public:*:*'], 
        roles: ['reader'],
        resources: ['*:$USER_ID$:*']
      }]
    };
    const token = '.' + Buffer.from(JSON.stringify(payload)).toString('base64') + '.';
    const areResourcesNarrowedDown = api.areTokenResourcesNarrowedDown(token);
    areResourcesNarrowedDown.should.be.false();
  });

});