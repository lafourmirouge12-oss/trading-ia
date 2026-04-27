'use strict';

import MetaApiClient from '../metaApi.client';

/**
 * metaapi.cloud Token Management API client
 */
export default class TokenManagementClient extends MetaApiClient {

  /**
   * Access rules manifest
   * @typedef {Object} ManifestAccessRule
   * @property {String} id application id
   * @property {String} application application name
   * @property {String} description application description
   * @property {Array<ManifestEntity>} entities application resources entities
   * @property {Array<ManifestService>} services application services
   * @property {Array<ManifestMethodGroup>} methodGroups application method groups
   * @property {Array<ManifestRoles>} roles application roles
   * @property {String} [entityCompositionDescription] application entity composition description
   */

  /**
   * Access rules manifest resource entity
   * @typedef {Object} ManifestEntity
   * @property {String} description entity description
   * @property {String} entity entity name
   * @property {String} [idDescription] entity id description
   */

  /**
   * Access rules manifest application service
   * @typedef {Object} ManifestService
   * @property {String} description service description
   * @property {String} service service name
   */

  /**
   * Access rules manifest application method group
   * @typedef {Object} ManifestMethodGroup
   * @property {String} group method group name
   * @property {String} description method group description
   * @property {Array<ManifestMethod>} methods method group methods
   */

  /**
   * Access rules manifest application method
   * @typedef {Object} ManifestMethod
   * @property {String} description method description
   * @property {Array<String>} method method name
   * @property {Array<String>} [scopes] method scopes
   */

  /**
   * Access rules manifest application roles
   * @typedef {Object} ManifestRoles
   * @property {String} description application roles description
   * @property {Array<String>} roles application roles
   */

  /**
   * Narrowed down token access rules
   * @typedef {Object} NarrowDownAccessRules
   * @property {Array<AccessRule>} accessRules applications access rules to grant
   */

  /**
   * Narrowed down token simplified access rules
   * @typedef {Object} NarrowDownSimplifiedAccessRules
   * @property {Array<AccessRuleResource>} [resources] resources to grant access to
   * @property {Array<String>} [roles] roles to grant access to
   * @property {Array<String>} [applications] applications to grant access to
   */

  /**
   * Narrowed down token access rule
   * @typedef {Object} AccessRule
   * @property {String} id application id to grant access to
   * @property {String} application application to grant access to
   * @property {String} service application service to grant access to
   * @property {Array<MethodGroups>} methodGroups application service methodGroups to
   * grant access to
   * @property {Array<AccessRuleResource>} resources application service resources 
   * to grant access to
   * @property {Array<String>} roles access rule roles to grant access to
   */

  /**
   * Narrowed token access rule method groups 
   * @typedef {Object} MethodGroups
   * @property {String} group method group
   * @property {Array<Method>} methods method group methods
   */

  /**
   * Method group method
   * @typedef {Object} Method
   * @property {String} method method
   * @property {Array<String>} [scopes] method scopes
   */

  /**
   * Narrowed token access rule resource 
   * @typedef {Object} AccessRuleResource
   * @property {String} entity entity
   * @property {String} id entity id
   */

  /**
   * New narrowed down token model
   * @typedef {Object} NarrowedDownToken
   * @property {String} token authorization token value
   */

  /**
   * Constructs token management API client instance
   * @param {HttpClient} httpClient HTTP client
   * @param {DomainClient} domainClient domain client
   */
  constructor(httpClient, domainClient) {
    super(httpClient, domainClient);
    this._host = `https://profile-api-v1.${domainClient.domain}`;
  }

  /**
   * Gets access rules manifest
   * @returns {Promise<Array<ManifestAccessRule>>} access rules manifest
   */
  getAccessRules() {
    if (this._isNotJwtToken()) {
      return this._handleNoAccessError('getAccessRules');
    }
    const opts = {
      url: `${this._host}/access-rule-manifest`,
      method: 'GET',
      headers: {
        'auth-token': this._token
      },
      json: true
    };
    return this._httpClient.request(opts, 'getAccessRules');
  }

  /**
   * Returns narrowed down token with given access rules
   * @param {NarrowDownAccessRules | NarrowDownSimplifiedAccessRules} narrowDownPayload narrow down payload
   * @param {Number} [validityInHours] token validity in hours
   * @return {Promise<NarrowedDownToken>} promise resolving with narrowed down token
   */
  narrowDownToken(accessRules, validityInHours) {
    if (this._isNotJwtToken()) {
      return this._handleNoAccessError('narrowDownToken');
    }
    if (validityInHours) {
      validityInHours = `?validity-in-hours=${validityInHours}`;
    }
    const opts = {
      url: `${this._host}/users/current/narrow-down-auth-token${validityInHours || ''}`,
      method: 'POST',
      headers: {
        'auth-token': this._token
      },
      json: true,
      data: accessRules
    };
    return this._httpClient.request(opts, 'narrowDownToken');
  }

}