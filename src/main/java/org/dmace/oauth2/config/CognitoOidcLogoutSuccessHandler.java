package org.dmace.oauth2.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;

public class CognitoOidcLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private final String logoutUrl;
    private final String clientId;

    public CognitoOidcLogoutSuccessHandler(String clientId, String logoutUrl) {
        this.clientId = clientId;
        this.logoutUrl = logoutUrl;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {

        return UriComponentsBuilder
                .fromUri(URI.create(logoutUrl))
                .queryParam("client_id", clientId)
                .queryParam("logout_uri", "http://localhost:8080/oauth2/authorization/cognito")
                .queryParam("response_type", "code")
                .encode(StandardCharsets.UTF_8)
                .build()
                .toUriString();
    }
}