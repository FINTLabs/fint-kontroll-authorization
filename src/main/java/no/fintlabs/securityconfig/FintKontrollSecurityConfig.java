package no.fintlabs.securityconfig;

import no.fintlabs.opa.OpaAuthorizationManager;
import no.vigoiks.resourceserver.security.FintJwtUserConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class FintKontrollSecurityConfig {

    @Autowired
    private OpaAuthorizationManager opaAuthorizationManager;

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange()
                .pathMatchers("/**")
                .access(opaAuthorizationManager)
                .anyExchange()
                .authenticated()
                .and()
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt()
                        .jwtAuthenticationConverter(new FintJwtUserConverter()));
        return http.build();
    }

}
