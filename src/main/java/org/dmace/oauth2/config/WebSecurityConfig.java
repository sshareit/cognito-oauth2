package org.dmace.oauth2.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfig {

    private final String clientId;
    private final String logoutUrl;

    public WebSecurityConfig(
            @Value("${spring.security.oauth2.client.registration.cognito.clientId}")
            String clientId,
            @Value("${cognito.logoutUrl}")
            String logoutUrl) {
        this.clientId = clientId;
        this.logoutUrl = logoutUrl;
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                .and()
                .authorizeHttpRequests(authorize -> authorize.requestMatchers("/").permitAll())
                .authorizeHttpRequests(authorize -> authorize.requestMatchers("/admin").hasRole(("ROLE_ADMIN")))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .oauth2Login(l -> l.userInfoEndpoint().userAuthoritiesMapper(new OidcAuthoritiesMapper()))
                .logout()
                .logoutSuccessHandler(new CognitoOidcLogoutSuccessHandler(clientId, logoutUrl));

        return http.build();
    }

}