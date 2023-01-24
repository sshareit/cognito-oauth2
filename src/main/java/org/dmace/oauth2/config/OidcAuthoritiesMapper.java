package org.dmace.oauth2.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.util.*;
import java.util.stream.Collectors;

public class OidcAuthoritiesMapper implements GrantedAuthoritiesMapper {

    @Override
    public Collection<SimpleGrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Set<SimpleGrantedAuthority> mappedAuthorities = new HashSet<>();

        Optional<OidcUserAuthority> awsAuthority = authorities.stream()
                .filter(grantedAuthority -> "OIDC_USER".equals(grantedAuthority.getAuthority()))
                .filter(grantedAuthority -> grantedAuthority instanceof OidcUserAuthority)
                .map(grantedAuthority -> (OidcUserAuthority) grantedAuthority)
                .findFirst();

        if (awsAuthority.isPresent()) {
            mappedAuthorities = mapAuthorities(awsAuthority.get());
        }

        return mappedAuthorities;
    }

    @SuppressWarnings("unchecked")
    private static Set<SimpleGrantedAuthority> mapAuthorities(OidcUserAuthority awsAuthority) {
        try {
            return ((ArrayList<String>) awsAuthority.getAttributes().get("cognito:groups")).stream()
                    .map(s -> new SimpleGrantedAuthority("ROLE_" + s.toUpperCase()))
                    .collect(Collectors.toSet());
        } catch (Exception e) {
            // User was created without groups
            return new HashSet<>();
        }
    }

}
