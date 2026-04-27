import TokenManagementClient, { AccessRuleResource, NarrowDownAccessRules, ManifestAccessRule, NarrowDownSimplifiedAccessRules } from "../clients/metaApi/tokenManagement.client";

/**
 * Exposes TokenManagement API logic to the consumers
 */
export default class TokenManagementApi {

  /**
   * Constructs a TokenManagement API instance
   * @param {TokenManagementClient} tokenManagementClient tokenManagement REST API client
   */
  constructor(tokenManagementClient: TokenManagementClient)

  /**
   * Gets access rules manifest
   */
  getAccessRules(): Promise<Array<ManifestAccessRule>>

  /**
   * Returns narrowed down token with given access rules
   * @param {NarrowDownAccessRules | NarrowDownSimplifiedAccessRules} narrowDownPayload narrow down payload
   * @param {Number} [validityInHours] token validity in hours, default is 24 hours
   * @returns {Promise<String>} narrowed down token
   */
  narrowDownToken(narrowDownPayload: NarrowDownAccessRules | NarrowDownSimplifiedAccessRules, validityInHours?: Number): Promise<String>

  /**
   * Returns narrowed down token with access to given applications
   * @param {Array<String>} applications applications to grant access to
   * @param {Number} [validityInHours] token validity in hours, default is 24 hours
   * @returns {Promise<String>} narrowed down token
   */
  narrowDownTokenApplications(applications: Array<String>, validityInHours?: Number): Promise<String>

  /**
   * Returns narrowed down token with access to given resources
   * @param {Array<AccessRuleResource>} resources resources to grant access to
   * @param {Number} [validityInHours] token validity in hours, default is 24 hours
   * @returns {Promise<String>} narrowed down token
   */
  narrowDownTokenResources(resources: Array<AccessRuleResource>, validityInHours?: Number): Promise<String>

  /**
   * Returns narrowed down token with access to given roles
   * @param {Array<String>} roles roles to grant access to
   * @param {Number} [validityInHours] token validity in hours, default is 24 hours
   * @returns {Promise<String>} narrowed down token
   */
  narrowDownTokenRoles(roles: Array<String>, validityInHours?: Number): Promise<String>

  /**
   * Checks if token resources access is restricted
   * @param {String} token token to check
   * @returns {Boolean} is token narrowed down
   */
  areTokenResourcesNarrowedDown(token: String): boolean
}