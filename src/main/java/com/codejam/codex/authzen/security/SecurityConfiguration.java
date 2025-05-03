package com.codejam.codex.authzen.security;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Main Security Configuration class that:
 * - Configures JWT-based OAuth2 authentication using HS256
 * - Sets global CORS and CSRF policies
 * - Applies secure HTTP headers
 * - Secures endpoints with role-based access
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@SecurityScheme(
        name = "Bearer Authentication",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        scheme = "bearer"
)
public class SecurityConfiguration {

    @Value("${spring.security.cors.allowed-origins}")
    private String allowedOrigins;

    @Value("${spring.security.cors.allowed-methods}")
    private String allowedMethods;

    @Value("${spring.security.cors.allowed-headers}")
    private String allowedHeaders;

    @Value("${spring.security.cors.exposed-headers}")
    private String exposedHeaders;

    @Value("${spring.security.cors.allow-credentials}")
    private boolean allowCredentials;

    @Value("${spring.security.cors.max-age}")
    private long maxAge;

    @Value("${jwt.secret}")
    private String jwtSecret;

    /**
     * Custom JWT Authentication Converter to extract roles from token claims.
     * Roles must be defined in the "roles" claim without any prefix.
     *
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<String> roles = jwt.getClaimAsStringList("roles");
            List<String> permissions = jwt.getClaimAsStringList("permissions");

            List<GrantedAuthority> authorities = new ArrayList<>();

            if (roles != null) {
                roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
            }

            if (permissions != null) {
                permissions.forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
            }

            return authorities;
        });

        return converter;
    }



    /**
     * Main Security Filter Chain configuration.
     * - Enables stateless session
     * - Disables CSRF (suitable for REST APIs)
     * - Applies JWT-based OAuth2 security
     * - Configures public and protected routes
     * - Adds secure headers and CORS support
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(corsFilter(), CorsFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/authenticate/auth/register",
                                "/api/authenticate/auth/login",
                                "/api/authenticate/auth/oauth",
                                "/api/authenticate/auth/reset-request",
                                "/api/authenticate/auth/reset-password",
                                "/api/authenticate/user/refresh",
                                "/css/**",
                                "/js/**",
                                "/swagger-ui/**",
                                "/reset-password/**",
                                "/api/authenticate/health",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/swagger-resources/**",
                                "/webjars/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                                .decoder(jwtDecoder())
                        )
                )
                .headers(headers -> {
                    headers
                            .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
                            .defaultsDisabled()
                            .addHeaderWriter(new StaticHeadersWriter("X-Content-Type-Options", "nosniff"))
                            .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                            .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN));
                });

        return http.build();
    }

    /**
     * Configures production-ready CORS filter with properties from application.yml
     * Implements strict CORS policy suitable for production use
     */
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        
        // Set allowed origins from properties (comma-separated list)
        config.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        
        // Set allowed methods from properties
        config.setAllowedMethods(Arrays.asList(allowedMethods.split(",")));
        
        // Set allowed headers from properties
        config.setAllowedHeaders(Arrays.asList(allowedHeaders.split(",")));
        
        // Set exposed headers from properties
        config.setExposedHeaders(Arrays.asList(exposedHeaders.split(",")));
        
        // Set allow credentials from properties
        config.setAllowCredentials(allowCredentials);
        
        // Set max age from properties
        config.setMaxAge(maxAge);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    /**
     * BCrypt password encoder bean for secure password hashing.
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configures JWT decoder for HS256 symmetric key.
     * Ensures key length is compliant with HS256 requirement (>= 256 bits).
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(keyBytes, "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(key).build();
    }
}
