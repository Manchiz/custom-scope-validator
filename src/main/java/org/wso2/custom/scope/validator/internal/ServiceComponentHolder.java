package org.wso2.custom.scope.validator.internal;

import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.user.core.service.RealmService;


public class ServiceComponentHolder {

    private static ServiceComponentHolder instance = new ServiceComponentHolder();
    private OAuthAdminServiceImpl oauthAdminService;

    private RealmService realmService;

    public static ServiceComponentHolder getInstance() {

        return instance;
    }


    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public OAuthAdminServiceImpl getOAuthAdminService() {

        return oauthAdminService;
    }

    public void setOAuthAdminService(OAuthAdminServiceImpl oauthAdminService) {

        this.oauthAdminService = oauthAdminService;
    }
}
