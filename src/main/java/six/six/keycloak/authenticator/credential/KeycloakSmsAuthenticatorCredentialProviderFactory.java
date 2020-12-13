package six.six.keycloak.authenticator.credential;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

/**
 * SMS code Internal management
 * Created by nickpack on 09/08/2017.
 */
public class KeycloakSmsAuthenticatorCredentialProviderFactory implements CredentialProviderFactory<KeycloakSmsAuthenticatorCredentialProvider> {
    public static final String PROVIDER_ID = "smsCode";
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new KeycloakSmsAuthenticatorCredentialProvider(session);
    }
}
