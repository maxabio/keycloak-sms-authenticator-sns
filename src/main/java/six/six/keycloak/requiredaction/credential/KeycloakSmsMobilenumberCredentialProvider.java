package six.six.keycloak.requiredaction.credential;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.OnUserCache;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Created by nickpack on 15/08/2017.
 */
public class KeycloakSmsMobilenumberCredentialProvider implements CredentialProvider, CredentialInputValidator, CredentialInputUpdater, OnUserCache {
    public static final String MOBILE_NUMBER = "mobile_number";
    public static final String CACHE_KEY = KeycloakSmsMobilenumberCredentialProvider.class.getName() + "." + MOBILE_NUMBER;
    private static Logger logger = Logger.getLogger(KeycloakSmsMobilenumberCredentialProvider.class);

    protected KeycloakSession session;

    private UserCredentialStore getCredentialStore() {
        return this.session.userCredentialManager();
    }

    public KeycloakSmsMobilenumberCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    public CredentialModel getSecret(RealmModel realm, UserModel user) {
        CredentialModel secret = null;
        if (user instanceof CachedUserModel) {
            CachedUserModel cached = (CachedUserModel)user;
            secret = (CredentialModel)cached.getCachedWith().get(CACHE_KEY);

        } else {
            List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, MOBILE_NUMBER);
            if (!creds.isEmpty()) secret = creds.get(0);
        }
        return secret;
    }


    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!MOBILE_NUMBER.equals(input.getType())) return false;
        if (!(input instanceof UserCredentialModel)) return false;
        UserCredentialModel credInput = (UserCredentialModel) input;
        List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, MOBILE_NUMBER);
        if (creds.isEmpty()) {
            CredentialModel secret = new CredentialModel();
            secret.setType(MOBILE_NUMBER);
            secret.setValue(credInput.getValue());
            secret.setCreatedDate(Time.currentTimeMillis());
            session.userCredentialManager().createCredential(realm ,user, secret);
        } else {
            creds.get(0).setValue(credInput.getValue());
            session.userCredentialManager().updateCredential(realm, user, creds.get(0));
        }
        session.userCache().evict(realm, user);
        return true;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        if (!MOBILE_NUMBER.equals(credentialType)) return;
        session.userCredentialManager().disableCredentialType(realm, user, credentialType);
        session.userCache().evict(realm, user);

    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        if (!session.userCredentialManager().getStoredCredentialsByType(realm, user, MOBILE_NUMBER).isEmpty()) {
            Set<String> set = new HashSet<>();
            set.add(MOBILE_NUMBER);
            return set;
        } else {
            return Collections.EMPTY_SET;
        }

    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return MOBILE_NUMBER.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!MOBILE_NUMBER.equals(credentialType)) return false;
        return getSecret(realm, user) != null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!MOBILE_NUMBER.equals(input.getType())) return false;
        if (!(input instanceof UserCredentialModel)) return false;

        String secret = getSecret(realm, user).getValue();

        return secret != null && ((UserCredentialModel)input).getValue().equals(secret);
    }

    @Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, MOBILE_NUMBER);
        if (!creds.isEmpty()) user.getCachedWith().put(CACHE_KEY, creds.get(0));
    }

    @Override
    public String getType() {
        logger.warn("KeycloakSmsMobilenumberCredentialProvider getType() called");
        return MOBILE_NUMBER;
    }

    @Override
    public CredentialModel createCredential(RealmModel realmModel, UserModel userModel, CredentialModel credentialModel) {
        logger.warn("KeycloakSmsMobilenumberCredentialProvider createCredential() called");
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        return this.getCredentialStore().createCredential(realmModel, userModel, credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realmModel, UserModel userModel, String credentialId) {
        logger.warn("KeycloakSmsMobilenumberCredentialProvider deleteCredential() called");
        return this.getCredentialStore().removeStoredCredential(realmModel, userModel, credentialId);
    }

    @Override
    public CredentialModel getCredentialFromModel(CredentialModel credentialModel) {
        logger.warn("KeycloakSmsMobilenumberCredentialProvider getCredentialFromModel() called");
        credentialModel.setType(MOBILE_NUMBER);
        return credentialModel;
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext credentialTypeMetadataContext) {
        logger.warn("KeycloakSmsMobilenumberCredentialProvider getCredentialTypeMetadata() called");
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName(KeycloakSmsMobilenumberCredentialProviderFactory.PROVIDER_ID)
                .helpText("sms-mobile-text")
                .createAction(KeycloakSmsMobilenumberCredentialProviderFactory.PROVIDER_ID)
                .removeable(false)
                .build(session);
    }
}
