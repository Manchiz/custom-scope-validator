package org.wso2.custom.scope.validator;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.oauth2.validators.JDBCScopeValidator;
import org.wso2.custom.scope.validator.internal.ServiceComponent;
//import org.wso2.custom.scope.validator.internal.CustomScopeValidatorDataHolder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

public class CustomScopeValidator extends JDBCScopeValidator {

    Log log = LogFactory.getLog(CustomScopeValidator.class);

    public static final String CHECK_ROLES_FROM_SAML_ASSERTION = "checkRolesFromSamlAssertion";
    public static final String RETRIEVE_ROLES_FROM_USERSTORE_FOR_SCOPE_VALIDATION =
            "retrieveRolesFromUserStoreForScopeValidation";
    private static final String SCOPE_VALIDATOR_NAME = "Custom scope validator";
    private static final String OPENID = "openid";
    private static final String ATTRIBUTE_SEPARATOR = FrameworkUtils.getMultiAttributeSeparator();


    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws
            UserStoreException, IdentityOAuth2Exception {

        List<String> validScopes = new ArrayList<>();

        validScopes = validateScope(tokReqMsgCtx.getScope(), tokReqMsgCtx.getAuthorizedUser(),
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());

        if (!validScopes.isEmpty()){
            tokReqMsgCtx.setScope(validScopes.toArray(new String[0]));
        }

        return true;

//        try {
//            validScopes = validateScope(tokReqMsgCtx.getScope(), tokReqMsgCtx.getAuthorizedUser(),
//                    tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
//
//            if (!validScopes.isEmpty()){
//                tokReqMsgCtx.setScope(validScopes.toArray(new String[0]));
//                return true;
//            }
//
//        } catch (UserStoreException e) {
//            throw new RuntimeException(e);
//        }
//
//        return false;
    }

    @Override
    public boolean validateScope(OAuthAuthzReqMessageContext authzReqMessageContext) throws
            UserStoreException, IdentityOAuth2Exception {

        List<String> validScopes = new ArrayList<>();

        validScopes = validateScope(authzReqMessageContext.getAuthorizationReqDTO().getScopes(),
                authzReqMessageContext.getAuthorizationReqDTO().getUser(),
                authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey());

        if (!validScopes.isEmpty()){
            authzReqMessageContext.setApprovedScope(validScopes.toArray(new String[0]));
        }

        return true;
//        try {
//            validScopes = validateScope(authzReqMessageContext.getAuthorizationReqDTO().getScopes(),
//                    authzReqMessageContext.getAuthorizationReqDTO().getUser(),
//                    authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey());
//        } catch (UserStoreException e) {
//            throw new RuntimeException(e);
//        }
//
//        if (validScopes != null){
//            //set msgcontext
//            authzReqMessageContext.setApprovedScope(validScopes.toArray(new String[0]));
//            return true;
//        }
//        return false;
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


        List<String> validScopes = new ArrayList<>();
        String[] userRoles = null;
        int tenantId = getTenantId(user);
//        if(ArrayUtils.contains(requestedScopes, OPENID)) {
//            validScopes.add(OPENID);
//            requestedScopes = (String[]) ArrayUtils.removeElement(requestedScopes, OPENID);
//        }

        // Remove OIDC scopes from the list if exists.
//        try {
//            String[] oidcScopes = OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService().getScopeNames();
//            for (String oidcScope : oidcScopes) {
//                validScopes.add(oidcScope);
//                requestedScopes = (String[]) ArrayUtils.removeElement(requestedScopes, oidcScope);
//            }
//
//        } catch (IdentityOAuthAdminException e) {
//            log.error("Unable to obtain OIDC scopes list.");
//            return new ArrayList<String>();
//        }
//
//        //If the token is not requested for specific scopes, return true
//        if (ArrayUtils.isEmpty(requestedScopes)) {
//            return validScopes;
//        }
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


        if (ArrayUtils.isNotEmpty(userRoles)) {
//            for (String scope : requestedScopes) {
//                if (!isScopeValid(scope, tenantId)) {
//                    // If the scope is not registered return false.
//                    log.error("Requested scope " + scope + " is invalid");
//                    return false;
//                }
//                if (!isUserAuthorizedForScope(scope, userRoles, tenantId)) {
//                    if (log.isDebugEnabled()) {
//                        log.debug("User " + user.getUserName() + "in not authorised for scope " + scope);
//                    }
//                    return false;
//                }
//            }
//            String[] validScopes;
//            List<String> validScopes = new ArrayList<>();
            for(String scope : requestedScopes){

                // Remove openid scope from the list if available
                if(Objects.equals(scope, OPENID)) {
                    validScopes.add(OPENID);
                    requestedScopes = (String[]) ArrayUtils.removeElement(requestedScopes, OPENID);
                }

                // Remove OIDC scopes from the list if exists.
                try {
                    if (ArrayUtils.contains(OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService().getScopeNames(), scope )) {
                        validScopes.add(scope);
                        requestedScopes = (String[]) ArrayUtils.removeElement(requestedScopes, scope);
                    }

                } catch (IdentityOAuthAdminException e) {
                    log.error("Unable to obtain OIDC scopes list.");
                    return validScopes;
                }

                if ((isScopeValid(scope, tenantId)) && (isScopeValid(scope, tenantId)) ){
                    validScopes.add(scope);
                }
            }
        }
        return validScopes;
    }

    private int getTenantId(User user) throws UserStoreException {

        int tenantId = IdentityTenantUtil.getTenantId(user.getTenantDomain());

        if (tenantId == 0 || tenantId == -1) {
            tenantId = IdentityTenantUtil.getTenantIdOfUser(user.getUserName());
        }

        return tenantId;
    }

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

    private String[] getUserRoles(User user) throws UserStoreException {

        UserStoreManager userStoreManager;
        String[] userRoles;
        boolean tenantFlowStarted = false;

        RealmService realmService = ServiceComponent.getRealmService();
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
        if (CollectionUtils.isNotEmpty(valuesOfGroups)) {
            for (RoleMapping roleMapping : identityProvider.getPermissionAndRoleConfig().getRoleMappings()) {
                if (roleMapping != null && roleMapping.getLocalRole() != null) {
                    if (valuesOfGroups.contains(roleMapping.getLocalRole().getLocalRoleName())) {
                        userRolesList.add(roleMapping.getLocalRole().getLocalRoleName());
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
                if (StringUtils.equals(entry.getKey().getRemoteClaim().getClaimUri(), OAuth2Constants.GROUPS)) {
                    return Arrays.asList(entry.getValue().split(Pattern.quote(ATTRIBUTE_SEPARATOR)));
                }
            }
        }
        return null;
    }

    private boolean isScopeValid(String scopeName, int tenantId) {

        Scope scope = null;

        try {
            scope = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopeByName(scopeName, tenantId);
        } catch (IdentityOAuth2ScopeServerException e) {
            log.error("Error while retrieving scope with name :" + scopeName);
        }

        return scope != null;
    }
//
//    @Override
//    public boolean validateScope(OAuth2TokenValidationMessageContext oAuth2TokenValidationMessageContext) {
//
//        return true;
//    }
//

    @Override
    public String getValidatorName() {

        return SCOPE_VALIDATOR_NAME;
    }
}
