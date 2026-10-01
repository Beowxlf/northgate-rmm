import com.northgate.rmm.IntrospectableAmrMapper;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.common.util.Time;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.representations.AccessToken;

/** Exercises the installed Keycloak calculation; contains no real identities. */
public class AmrMapperTest {
    @SuppressWarnings("unchecked")
    static <T> T stub(Class<T> type, Map<String, Object> results) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
            (proxy, method, args) -> results.get(method.getName()));
    }

    static Object claim(boolean completed, String maxAge, boolean include) {
        AuthenticatorConfigModel executionConfig = new AuthenticatorConfigModel();
        Map<String, String> settings = new HashMap<>();
        settings.put("default.reference.value", "otp");
        if (maxAge != null) settings.put("default.reference.maxAge", maxAge);
        executionConfig.setConfig(settings);
        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setAuthenticatorConfig("synthetic-config");
        RealmModel realm = stub(RealmModel.class, Map.of(
            "getAuthenticationExecutionById", execution,
            "getAuthenticatorConfigById", executionConfig));
        String notes = completed
            ? "{\"synthetic-otp-execution\":" + (Time.currentTime() - 60) + "}"
            : "{}";
        UserSessionModel user = stub(UserSessionModel.class, Map.of(
            "getNote", notes, "getRealm", realm));
        AuthenticatedClientSessionModel client = stub(AuthenticatedClientSessionModel.class,
            Map.of("getUserSession", user));
        ClientSessionContext context = stub(ClientSessionContext.class,
            Map.of("getClientSession", client));
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setConfig(Map.of("introspection.token.claim", Boolean.toString(include)));
        TokenIntrospectionTokenMapper mapper = new IntrospectableAmrMapper();
        AccessToken result = mapper.transformIntrospectionToken(new AccessToken(), model,
            null, user, context);
        return result.getOtherClaims().get("amr");
    }

    public static void main(String[] args) {
        if (!List.of("otp").equals(claim(true, "28800", true)))
            throw new AssertionError("Completed, valid OTP must appear in introspection");
        if (!List.of().equals(claim(true, null, true)))
            throw new AssertionError("Missing validity must not assert old OTP");
        if (!List.of().equals(claim(true, "30", true)))
            throw new AssertionError("Expired OTP must not be asserted");
        if (!List.of().equals(claim(false, "28800", true)))
            throw new AssertionError("Uncompleted OTP must not be asserted");
        if (claim(true, "28800", false) != null)
            throw new AssertionError("Disabled introspection mapping must stay disabled");
        System.out.println("PASS: valid OTP, missing validity, expired OTP, absent OTP, disabled mapper");
    }
}
