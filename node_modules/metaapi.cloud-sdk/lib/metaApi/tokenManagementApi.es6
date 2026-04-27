'use strict';

/**
 * Exposes TokenManagement API logic to the consumers
 */
export default class TokenManagementApi {

  /**
   * Constructs a TokenManagement API instance
   * @param {TokenManagementClient} tokenManagementClient tokenManagement REST API client
   */
  constructor(tokenManagementClient) {
    this._tokenManagementClient = tokenManagementClient;
  }

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
   * Gets access rules manifest
   * @returns {Promise<Array<ManifestAccessRule>>} access rules manifest
   */
  getAccessRules() {
    return this._tokenManagementClient.getAccessRules();
  }

  /**
   * Returns narrowed down token with given access rules
   * @param {NarrowDownAccessRules | NarrowDownSimplifiedAccessRules} narrowDownPayload narrow down payload
   * @param {Number} [validityInHours] token validity in hours, default is 24 hours
   * @returns {Promise<String>} narrowed down token
   */
  async narrowDownToken(narrowDownPayload, validityInHours) {
    const narrowedToken = await this._tokenManagementClient.narrowDownToken(narrowDownPayload, validityInHours);
    return narrowedToken.token;
  }

  /**
   * Returns narrowed down token with access to given resources
   * @param {Array<AccessRuleResource>} resources resources to grant access to
   * @param {Number} [validityInHours] token validity in hours, default is 24 hours
   * @returns {Promise<String>} narrowed down token
   */
  async narrowDownTokenResources(resources, validityInHours) {
    const narrowedToken = await this._tokenManagementClient.narrowDownToken(
      { resources }, validityInHours
    );
    return narrowedToken.token;
  }

  /**
   * Returns narrowed down token with access to given roles
   * @param {Array<String>} roles roles to grant access to
   * @param {Number} [validityInHours] token validity in hours, default is 24 hours
   * @returns {Promise<String>} narrowed down token
   */
  async narrowDownTokenRoles(roles, validityInHours) {
    const narrowedToken = await this._tokenManagementClient.narrowDownToken({ roles }, validityInHours);
    return narrowedToken.token;
  }

  /**
   * Returns narrowed down token with access to given applications
   * @param {Array<String>} applications applications to grant access to
   * @param {Number} [validityInHours] token validity in hours, default is 24 hours
   * @returns {Promise<String>} narrowed down token
   */
  async narrowDownTokenApplications(applications, validityInHours) {
    const narrowedToken = await this._tokenManagementClient.narrowDownToken({ applications }, validityInHours);
    return narrowedToken.token;
  }

  /**
   * Checks if token resources access is restricted
   * @param {String} token token to check
   * @returns {Boolean} is token narrowed down
   */
  areTokenResourcesNarrowedDown(token) {
    const parsedPayload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    const areResourcesRestricted = parsedPayload.accessRules.find(rule => {
      return rule.resources.find(resource => !/^\*:\S*:\*$/.test(resource));
    });
    if (areResourcesRestricted) {
      return true;
    }
    return false;
  }
}