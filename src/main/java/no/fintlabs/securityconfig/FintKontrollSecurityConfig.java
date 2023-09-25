package no.fintlabs.securityconfig;

import no.fintlabs.opa.KontrollAuthorizationManager;
import no.fintlabs.util.JwtUserConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class FintKontrollSecurityConfig {

    @Autowired
    private KontrollAuthorizationManager kontrollAuthorizationManager;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/swagger-ui/**", "/swagger-ui**", "/api/api-docs/**", "/api/api-docs**").permitAll()
                        .anyRequest().access(kontrollAuthorizationManager)
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(new JwtUserConverter())));
        return http.build();
    }
}
