package ru.kuznetsov.shop.auth.service;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import lombok.RequiredArgsConstructor;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import ru.kuznetsov.shop.represent.contract.auth.AuthContract;
import ru.kuznetsov.shop.represent.dto.auth.LoginPasswordDto;
import ru.kuznetsov.shop.represent.dto.auth.TokenDto;
import ru.kuznetsov.shop.represent.dto.auth.UserDto;

import java.text.ParseException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class KeycloakAuthService implements AuthContract {

    private static final String REALMS = "/realms";
    private static final String PROTOCOL = "/protocol";
    private static final String OPENID_CONNECT = "/openid-connect";
    private static final String TOKEN = "/token";
    private static final String INTROSPECT = "/introspect";

    private static final String USER_ID_CLAIM = "sub";
    private static final String USER_USERNAME_CLAIM = "preferred_username";
    private static final String USER_EMAIL_CLAIM = "email";
    private static final String USER_EMAIL_VERIFIED_CLAIM = "email_verified";

    @Value("${keycloak.serverUrl}")
    private String serverUrl;
    @Value("${keycloak.realm}")
    private String realm;
    @Value("${keycloak.clientId}")
    private String clientId;
    @Value("${keycloak.clientSecret}")
    private String clientSecret;

    Logger logger = LoggerFactory.getLogger(KeycloakAuthService.class);

    public TokenDto getToken(LoginPasswordDto authHeader) {
        Keycloak client = getConfidentialClient(authHeader);
        try {
            AccessTokenResponse accessToken = client.tokenManager().getAccessToken();
            return TokenDto.builder()
                    .token(accessToken.getToken())
                    .expiresIn(accessToken.getExpiresIn())
                    .refreshToken(accessToken.getRefreshToken())
                    .refreshExpiresIn(accessToken.getRefreshExpiresIn())
                    .tokenType(accessToken.getTokenType())
                    .sessionState(accessToken.getSessionState())
                    .otherClaims(accessToken.getOtherClaims())
                    .scope(accessToken.getScope())
                    .error(accessToken.getError())
                    .errorDescription(accessToken.getErrorDescription())
                    .build();
        } catch (Exception e) {
            logger.error("GetToken error", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public Boolean isTokenValid(String token) {
        String introspectSubPath = REALMS + "/" + realm + PROTOCOL + OPENID_CONNECT + TOKEN + INTROSPECT;

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> introspectParams = new LinkedMultiValueMap<>();
        introspectParams.add("client_id", clientId);
        introspectParams.add("client_secret", clientSecret);
        introspectParams.add("token", token.replace("Bearer ", ""));

        var request = new HttpEntity<>(introspectParams, headers);
        RestTemplate restTemplate = new RestTemplate();

        ResponseEntity<Map> response = restTemplate.postForEntity(
                serverUrl + introspectSubPath,
                request,
                Map.class
        );

        logger.debug("Got response from keycloak: {}", response.getBody());

        return response.getBody() != null && (Boolean) response.getBody().get("active");
    }

    @Override
    public Collection<String> getUserRoles(String token) {
        try {
            JWT jwt = JWTParser.parse(token.replace("Bearer ", ""));
            return ((Map<String, List<String>>) jwt.getJWTClaimsSet().getClaim("realm_access"))
                    .get("roles")
                    .stream()
                    .filter(role -> role.startsWith("ROLE_"))
                    .map(role -> role.substring(5))
                    .toList();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public UserDto getUserInfo(String token) {
        try {
            JWTClaimsSet claimsSet = JWTParser
                    .parse(token.replace("Bearer ", ""))
                    .getJWTClaimsSet();

            return UserDto.builder()
                    .id(UUID.fromString((String) claimsSet.getClaim(USER_ID_CLAIM)))
                    .username((String) claimsSet.getClaim(USER_USERNAME_CLAIM))
                    .email((String) claimsSet.getClaim(USER_EMAIL_CLAIM))
                    .emailVerified(Boolean.valueOf((String) claimsSet.getClaim(USER_EMAIL_VERIFIED_CLAIM)))
                    .build();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private Keycloak getConfidentialClient(LoginPasswordDto authHeader) {
        return KeycloakBuilder.builder()
                .grantType(OAuth2Constants.PASSWORD)
                .serverUrl(serverUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .username(authHeader.getLogin())
                .password(authHeader.getPassword())
                .build();
    }
}
