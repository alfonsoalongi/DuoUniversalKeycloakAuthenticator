package com.instipod.duouniversal;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.Collections;
import java.util.List;

public class DuoUniversalAuthenticatorFactory implements org.keycloak.authentication.AuthenticatorFactory {
    public static final String PROVIDER_ID = "duo-universal";

    protected static final String DUO_API_HOSTNAME = "duoApiHostname";
    protected static final String DUO_INTEGRATION_KEY = "duoIntegrationKey";
    protected static final String DUO_SECRET_KEY = "duoSecretKey";
    protected static final String DUO_FAIL_SAFE = "duoFailSafe";
    protected static final String DUO_CUSTOM_CLIENT_IDS = "duoClientIds";
    protected static final String DUO_CONDITIONAL_ROLES = "duoCondUserRole";
    protected static final String DUO_SKIP_CONDITIONAL_ROLES = "duoSkipCondUserRole";

    private final static List<ProviderConfigProperty> commonConfig;

    static {
        commonConfig = Collections.unmodifiableList(ProviderConfigurationBuilder.create()
                .property().name(DUO_API_HOSTNAME).label("Duo API Hostname").helpText("Domain name to contact").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(DUO_INTEGRATION_KEY).label("Duo Integration Key").helpText("Obtained from admin console").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(DUO_SECRET_KEY).label("Duo Secret Key").helpText("Obtained from admin console").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(DUO_FAIL_SAFE).label("Fail Safe").helpText("With this enabled, users will be able to login if Duo is not reachable").type(ProviderConfigProperty.BOOLEAN_TYPE).add()
                .property().name(DUO_CUSTOM_CLIENT_IDS).label("Client Overrides").helpText("Comma separated list of client-specific Duo key overrides (keycloak client id, duo client id, duo secret, (optional) API hostname)").type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE).add()
                .property().name(DUO_CONDITIONAL_ROLES).label("Apply to user roles").helpText("If set, the DUO authentication will be applied to users who have at least one of these roles. This option has precedence on the 'Skip for user roles' option. Click 'Select Role' button to browse roles, or just type it in the textbox. To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole").type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE).add()
                .property().name(DUO_SKIP_CONDITIONAL_ROLES).label("Skip for user roles").helpText("If set, the DUO authentication will NOT be applied to users who have at least one of these roles. Click 'Select Role' button to browse roles, or just type it in the textbox. To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole").type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE).add()
                .build()
        );
    }

    @Override
    public String getDisplayType() {
        return "Duo Universal MFA";
    }

    @Override
    public String getReferenceCategory() {
        return "MFA";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.ALTERNATIVE, AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Uses the Duo Universal Prompt webservice to provide 2FA services.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return commonConfig;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return DuoUniversalAuthenticator.SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {
        //noop
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        //noop
    }

    @Override
    public void close() {
        //noop
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
