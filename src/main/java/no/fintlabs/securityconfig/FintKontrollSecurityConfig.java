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
                .authorizeRequests()
                .antMatchers("/swagger-ui/**", "/swagger-ui**", "/api/api-docs/**", "/api/api-docs**").permitAll()
                .anyRequest().authenticated()
                .and()
                .authorizeRequests()
                .accessDecisionManager(kontrollAuthorizationManager)
                .and()
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt()
                        .jwtAuthenticationConverter(new JwtUserConverter()));
        return http.build();
    }
}
