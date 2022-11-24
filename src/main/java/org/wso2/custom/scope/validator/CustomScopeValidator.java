package org.wso2.custom.scope.validator;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.JDBCScopeValidator;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.custom.scope.validator.internal.ServiceComponentHolder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The custom scope validator extends the default JDBC scope validator to override its default behaviour of terminating
 * the authentication flow if any unauthorized scopes were requested. This extended scope validator allows the
 * authentication flow to complete for any scope request while dropping the scopes which are not authorized for the
 * user based on roles assigned.
 */
public class CustomScopeValidator extends JDBCScopeValidator {

    private static final Log log = LogFactory.getLog(CustomScopeValidator.class);

    private static final String SCOPE_VALIDATOR_NAME = "Custom scope validator";
    private static final String OPENID = "openid";
    private static final String ATTRIBUTE_SEPARATOR = FrameworkUtils.getMultiAttributeSeparator();
    private static final String GROUPS = "groups";

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws
            UserStoreException, IdentityOAuth2Exception {

        List<String> validScopes = new ArrayList<>();

        validScopes = validateScope(tokReqMsgCtx.getScope(), tokReqMsgCtx.getAuthorizedUser(),
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());

        tokReqMsgCtx.setScope(validScopes.toArray(new String[0]));

        if (validScopes.isEmpty() && log.isDebugEnabled()) {
            log.debug("Unable to find any valid scopes for the user");
        }
        return true;
    }

    @Override
    public boolean validateScope(OAuthAuthzReqMessageContext authzReqMessageContext) throws
            UserStoreException, IdentityOAuth2Exception {

        List<String> validScopes = new ArrayList<>();

        validScopes = validateScope(authzReqMessageContext.getAuthorizationReqDTO().getScopes(),
                authzReqMessageContext.getAuthorizationReqDTO().getUser(),
                authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey());

        authzReqMessageContext.setApprovedScope(validScopes.toArray(new String[0]));

        if (!validScopes.isEmpty() && log.isDebugEnabled()) {
            log.debug("Unable to find any valid scopes for the user");
        }
        return true;
    }

    /**
     * Validate given set of scopes against an authenticated user.
     *
     * @param requestedScopes Scopes to be validated.
     * @param user            Authenticated user.
     * @param clientId        Client ID.
     * @return True is all scopes are valid. False otherwise.
     * @throws UserStoreException      If were unable to get tenant or user roles.
     * @throws IdentityOAuth2Exception If were unable to get Identity provider.
     */
    private List<String> validateScope(String[] requestedScopes, AuthenticatedUser user, String clientId)
            throws UserStoreException, IdentityOAuth2Exception {


        List<String> authorizedScopes = new ArrayList<>();
        String[] userRoles = null;
        int tenantId = getTenantId(user);

        /*
        Here we handle scope validation for federated user and local user separately.
        For local users - user store is used to get user roles.
        For federated user - get user roles from user attributes.
        Note that if there is association between a federated user and local user () 'Assert identity using mapped local
        subject identifier' flag will be set as true. So authenticated user will be associated local user not
        federated user.
         */
        if (user.isFederatedUser()) {
            /*
            There is a flow where 'Assert identity using mapped local subject identifier' flag enabled but the
            federated user doesn't have any association in localIDP, to handle this case we check for 'Assert
            identity using mapped local subject identifier' flag and get roles from userStore.
             */
            if (isSPAlwaysSendMappedLocalSubjectId(clientId)) {
                userRoles = getUserRoles(user);
            } else {
                // Handle not account associated federated users.
                userRoles = getUserRolesForNotAssociatedFederatedUser(user);
            }
        } else {
            userRoles = getUserRoles(user);
        }

        if (log.isDebugEnabled()) {
            log.debug(String.format("Assigned roles for user %s are %s.", user, Arrays.toString(userRoles)));
            log.debug(String.format("Requested scopes for user %s are %s.", user, Arrays.toString(requestedScopes)));

        }

        if (ArrayUtils.isNotEmpty(userRoles)) {

            // Allow OIDC scopes without role validation.
            try {
                String[] oidcScopes = ServiceComponentHolder.getInstance().getOAuthAdminService().getScopeNames();
                for (String oidcScope : oidcScopes) {

                    if (ArrayUtils.contains(requestedScopes, oidcScope)) {
                        requestedScopes = (String[]) ArrayUtils.removeElement(requestedScopes, oidcScope);
                        authorizedScopes.add(oidcScope);
                    }
                }

            } catch (IdentityOAuthAdminException e) {
                log.error("Unable to obtain OIDC scopes list.", e);
            }

            for (String scope : requestedScopes) {
                if ((isScopeValid(scope, tenantId)) && (isUserAuthorizedForScope(scope, userRoles, tenantId))) {
                    authorizedScopes.add(scope);

                    if (log.isDebugEnabled()) {
                        log.debug(scope + " Scope added to the authorizedScopes list");
                    }
                }
            }
        }
        return authorizedScopes;
    }

    /**
     * Return Tenant ID for authenticated user.
     *
     * @param user Authenticated user.
     * @return Tenant ID for authenticated user.
     * @throws UserStoreException If were unable to get tenant for authenticated user.
     */

    private int getTenantId(User user) throws UserStoreException {

        int tenantId = IdentityTenantUtil.getTenantId(user.getTenantDomain());

        if (tenantId == 0 || tenantId == -1) {
            tenantId = IdentityTenantUtil.getTenantIdOfUser(user.getUserName());
        }

        return tenantId;
    }

    /**
     * Check whether federated user has associated federated users in locally.
     *
     * @param clientId Client ID.
     * @return True is there associated account for federated user. False otherwise.
     * @throws IdentityOAuth2Exception If were unable to get Service Provider or claim configuration for Service Provider.
     */

    private boolean isSPAlwaysSendMappedLocalSubjectId(String clientId) throws IdentityOAuth2Exception {

        ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId);
        if (serviceProvider != null) {
            ClaimConfig claimConfig = serviceProvider.getClaimConfig();
            if (claimConfig != null) {
                return claimConfig.isAlwaysSendMappedLocalSubjectId();
            } else {
                throw new IdentityOAuth2Exception("Unable to find claim configuration for service provider of client " +
                        "id " + clientId);
            }
        } else {
            throw new IdentityOAuth2Exception("Unable to find service provider for client id " + clientId);
        }
    }

    /**
     * Get a user role if the user is an associated federated user.
     *
     * @param user Authenticated user.
     * @return user roles associated with authenticated user.
     * @throws UserStoreException If were unable to get user roles associated with authenticated user.
     */

    private String[] getUserRoles(User user) throws UserStoreException {

        UserStoreManager userStoreManager;
        String[] userRoles;
        boolean tenantFlowStarted = false;

        RealmService realmService = ServiceComponentHolder.getInstance().getRealmService();
        int tenantId = getTenantId(user);
        try {
            if (tenantId != MultitenantConstants.SUPER_TENANT_ID) {
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(
                        realmService.getTenantManager().getDomain(tenantId), true);
                tenantFlowStarted = true;
            }

            userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            userRoles = userStoreManager.getRoleListOfUser(
                    MultitenantUtils.getTenantAwareUsername(user.toFullQualifiedUsername()));
        } finally {
            if (tenantFlowStarted) {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }

        if (ArrayUtils.isNotEmpty(userRoles)) {
            if (log.isDebugEnabled()) {
                StringBuilder logMessage = new StringBuilder("Found roles of user ");
                logMessage.append(user.getUserName());
                logMessage.append(" ");
                logMessage.append(String.join(",", userRoles));
                log.debug(logMessage.toString());
            }
        }
        return userRoles;
    }

    /**
     * Get a user role if the user is not an associated federated user.
     *
     * @param user Authenticated user.
     * @return user roles associated with the authenticated user.
     * @throws IdentityOAuth2Exception If were unable to get user roles associated with authenticated user.
     */

    private String[] getUserRolesForNotAssociatedFederatedUser(AuthenticatedUser user)
            throws IdentityOAuth2Exception {

        List<String> userRolesList = new ArrayList<>();
        IdentityProvider identityProvider =
                OAuth2Util.getIdentityProvider(user.getFederatedIdPName(), user.getTenantDomain());
        /*
        Values of Groups consists unmapped federated roles, mapped local roles and Internal/everyone corresponding to
        authenticated user.
        Role mapping consists mapped federated roles with local roles corresponding to IDP.
        By cross checking federated role mapped local roles and values of groups we can filter valid local roles which
        mapped to the federated role of authenticated user.
         */
        List<String> valuesOfGroups = getValuesOfGroupsFromUserAttributes(user.getUserAttributes());
        String localRole;

        if (CollectionUtils.isNotEmpty(valuesOfGroups)) {
            for (RoleMapping roleMapping : identityProvider.getPermissionAndRoleConfig().getRoleMappings()) {
                if (roleMapping != null && roleMapping.getLocalRole() != null) {
                    if(roleMapping.getLocalRole().getUserStoreId() != null){
                        localRole = roleMapping.getLocalRole().getUserStoreId().toUpperCase().concat(CarbonConstants.DOMAIN_SEPARATOR).concat(roleMapping.getLocalRole().getLocalRoleName());
                    } else {
                        localRole = roleMapping.getLocalRole().getLocalRoleName();
                    }
                    if (valuesOfGroups.contains(localRole)) {
                        userRolesList.add(localRole);
                    }
                }
            }
        }
        // By default we provide Internal/everyone role for all users.
        String internalEveryoneRole = OAuth2Util.getInternalEveryoneRole(user);
        if (StringUtils.isNotBlank(internalEveryoneRole)) {
            userRolesList.add(internalEveryoneRole);
        }
        return userRolesList.toArray(new String[0]);
    }

    /**
     * Get groups params Roles from User attributes.
     *
     * @param userAttributes User Attributes
     * @return User attribute map
     */

    private List<String> getValuesOfGroupsFromUserAttributes(Map<ClaimMapping, String> userAttributes) {

        if (MapUtils.isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                if (StringUtils.equals(entry.getKey().getRemoteClaim().getClaimUri(), GROUPS)) {
                    return Arrays.asList(entry.getValue().split(Pattern.quote(ATTRIBUTE_SEPARATOR)));
                }
            }
        }
        return null;
    }

    /**
     * Get a user role if the user is not an associated federated user.
     *
     * @param scopeName requested scope.
     * @return True, if the scope is valid. False otherwise.
     */

    private boolean isScopeValid(String scopeName, int tenantId) {

        Scope scope = null;

        try {
            scope = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopeByName(scopeName, tenantId);
        } catch (IdentityOAuth2ScopeServerException e) {
            log.error("Error while retrieving scope with name :" + scopeName, e);
        }

        if (log.isDebugEnabled() && scope == null) {
            log.debug(scopeName + " Scope is not valid under the tenant id: " + tenantId);
        }

        return scope != null;
    }

    /**
     * Validate scopes which bind with user roles.
     *
     * @param scopeName requested scope
     * @param userRoles User roles
     * @param tenantId  Tenant Id .
     * @return True if the user has requested scope. False otherwise.
     * @throws IdentityOAuth2Exception If were unable to valid the scope against the user.
     */

    private boolean isUserAuthorizedForScope(String scopeName, String[] userRoles, int tenantId)
            throws IdentityOAuth2Exception {

        Set<String> rolesOfScope = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().
                getBindingsOfScopeByScopeName(scopeName, tenantId);

        if (CollectionUtils.isEmpty(rolesOfScope)) {
            if (log.isDebugEnabled()) {
                log.debug("Did not find any roles associated to the scope " + scopeName);
            }
            return true;
        }

        if (log.isDebugEnabled()) {
            StringBuilder logMessage = new StringBuilder("Found roles of scope '" + scopeName + "' ");
            logMessage.append(String.join(",", rolesOfScope));
            log.debug(logMessage.toString());
        }

        if (ArrayUtils.isEmpty(userRoles)) {
            if (log.isDebugEnabled()) {
                log.debug("User does not have required roles for scope " + scopeName);
            }
            return false;
        }

        // Check if the user still has a valid role for this scope.
        Set<String> scopeRoles = new HashSet<>(rolesOfScope);
        rolesOfScope.retainAll(Arrays.asList(userRoles));

        if (rolesOfScope.isEmpty()) {
            // when the role is an internal one, check if the user has valid role
            boolean validInternalUserRole = validateInternalUserRoles(scopeRoles, userRoles);

            if (validInternalUserRole) {
                return true;
            }
            if (log.isDebugEnabled()) {
                log.debug("User does not have required roles for scope " + scopeName);
            }
            return false;
        }

        return true;
    }

    /**
     * This method used to validate scopes which bind with internal roles
     *
     * @param scopeRoles Roles in scope.
     * @param userRoles  User roles
     * @return True if the user has requested scope. False otherwise.
     */

    private boolean validateInternalUserRoles(Set<String> scopeRoles, String[] userRoles) {

        for (String role : scopeRoles) {
            int index = role.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
            if (index > 0) {
                String domain = role.substring(0, index);
                if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain)) {
                    for (String userRole : userRoles) {
                        if (role.equalsIgnoreCase(userRole)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    @Override
    public String getValidatorName() {

        return SCOPE_VALIDATOR_NAME;
    }
}
