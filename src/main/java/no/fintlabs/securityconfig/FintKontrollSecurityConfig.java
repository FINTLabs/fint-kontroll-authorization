package no.fintlabs.securityconfig;

import lombok.RequiredArgsConstructor;
import no.fintlabs.opa.KontrollAuthorizationManager;
import no.fintlabs.util.JwtUserConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class FintKontrollSecurityConfig {

    private final KontrollAuthorizationManager kontrollAuthorizationManager;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .anyRequest().access(kontrollAuthorizationManager)
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(new JwtUserConverter()))
                .authenticationEntryPoint(authenticationEntryPoint))
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .accessDeniedHandler(accessDeniedHandler)
                );
        return http.build();
    }
}
