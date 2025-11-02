package ru.kuznetsov.shop.auth.service;

import com.nimbusds.jwt.JWTParser;
import jakarta.ws.rs.NotAuthorizedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.CollectionUtils;
import ru.kuznetsov.shop.represent.dto.auth.LoginPasswordDto;
import ru.kuznetsov.shop.represent.dto.auth.TokenDto;

import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class KeycloakAuthServiceTest {

    protected final static String TEST_USER_LOGIN = "shop_test";
    protected final static String TEST_USER_PASSWORD = "test";

    private final KeycloakAuthService keycloakAuthService = new KeycloakAuthService();

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(keycloakAuthService, "serverUrl", "http://localhost:8180");
        ReflectionTestUtils.setField(keycloakAuthService, "realm", "shop");
        ReflectionTestUtils.setField(keycloakAuthService, "clientId", "shop-app-test");
        ReflectionTestUtils.setField(keycloakAuthService, "clientSecret", "0nKwcagdO62xNuEmjMt2lJms2qzdr2A5");
    }

    @Test
    void getToken_correct_User() throws ParseException {
        TokenDto response = getToken(TEST_USER_LOGIN, TEST_USER_PASSWORD);

        assertNotNull(response);
        assertNotNull(response.getToken());
        assertNotNull(response.getRefreshToken());
        assertNotNull(response.getTokenType());
        assertNotNull(response.getSessionState());
        assertNotNull(response.getScope());
        assertNull(response.getError());
        assertNull(response.getErrorDescription());
        assertTrue(response.getExpiresIn() > 0);

        assertDoesNotThrow(() -> JWTParser.parse(response.getToken().replace("Bearer ", "")));

        Map<String, Object> claimsSet = JWTParser.parse(response.getToken().replace("Bearer ", "")).getJWTClaimsSet().getClaims();

        assertTrue(((Date) claimsSet.get("exp")).after(new Date()));
    }

    @Test
    void getToken_wrong_login_User() {
        RuntimeException runtimeException = assertThrows(
                RuntimeException.class,
                () -> getToken(TEST_USER_LOGIN + "123", TEST_USER_PASSWORD)
        );
        assertEquals(NotAuthorizedException.class, runtimeException.getCause().getClass());
    }

    @Test
    void getToken_wrong_pass_User() {
        RuntimeException runtimeException = assertThrows(
                RuntimeException.class,
                () -> getToken(TEST_USER_LOGIN, TEST_USER_PASSWORD + "123")
        );
        assertEquals(NotAuthorizedException.class, runtimeException.getCause().getClass());
    }

    @Test
    void isTokenValid() {
        TokenDto response = getToken(TEST_USER_LOGIN, TEST_USER_PASSWORD);

        assertTrue(keycloakAuthService.isTokenValid(response.getToken()));
    }

    @Test
    void getUserRoles() {
        TokenDto response = getToken(TEST_USER_LOGIN, TEST_USER_PASSWORD);

        Collection<String> userRoles = keycloakAuthService.getUserRoles(response.getToken());

        assertFalse(CollectionUtils.isEmpty(userRoles));

        for (String userRole : userRoles) {
            assertFalse(userRole.contains("ROLE"));
        }

        assertTrue(userRoles.contains("USER"));
        assertTrue(userRoles.contains("TEST"));
    }

    private TokenDto getToken(String login, String password) {
        LoginPasswordDto request = new LoginPasswordDto(login, password);

        return keycloakAuthService.getToken(request);
    }
}