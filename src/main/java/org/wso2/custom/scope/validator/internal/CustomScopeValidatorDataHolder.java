package org.wso2.custom.scope.validator.internal;

import org.wso2.carbon.user.core.service.RealmService;

public class CustomScopeValidatorDataHolder {

    private static CustomScopeValidatorDataHolder instance = new CustomScopeValidatorDataHolder();

    private RealmService realmService;

    private CustomScopeValidatorDataHolder() {

    }

    public static CustomScopeValidatorDataHolder getInstance() {

        return instance;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }
}
