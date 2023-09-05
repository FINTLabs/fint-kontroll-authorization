package no.fintlabs.util;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private Map<String, String> authoritiesMap = new HashMap<>() {
        {
            this.put("scope", "SCOPE_");
        }
    };
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        for (Map.Entry<String, String> claimPrefixEntry : this.authoritiesMap.entrySet()) {
            String claimKey = claimPrefixEntry.getKey();
            if (jwt.hasClaim(claimKey)) {
                authorities.addAll(extractAuthorities(jwt, claimKey, claimPrefixEntry.getValue()));
            }
        }

        return new JwtAuthenticationToken(jwt, authorities);
    }

    public JwtConverter addMapping(String claimName, String prefix) {
        this.authoritiesMap.put(claimName, prefix);
        return this;
    }

    public JwtConverter setMappings(HashMap<String, String> authoritiesMap) {
        this.authoritiesMap = authoritiesMap;
        return this;
    }

    private List<GrantedAuthority> extractAuthorities(Jwt jwt, String claimName, String prefix) {
        Object claim = jwt.getClaim(claimName);
        List<GrantedAuthority> authorities = new ArrayList<>();

        if (claim instanceof String) {
            String[] claimArray = ((String) claim).split(" ");
            for (String authority : claimArray) {
                authorities.add(new SimpleGrantedAuthority(prefix + authority));
            }
        } else if (claim instanceof Collection) {
            authorities = ((Collection<?>) claim).stream()
                    .filter(authority -> authority instanceof String)
                    .map(authority -> new SimpleGrantedAuthority(prefix + authority))
                    .collect(Collectors.toList());
        }

        return authorities;
    }
}
