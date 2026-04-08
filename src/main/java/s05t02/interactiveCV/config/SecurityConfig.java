package s05t02.interactiveCV.config;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;
import s05t02.interactiveCV.globalVariables.ApiPaths;
import s05t02.interactiveCV.service.security.CustomReactiveAuthenticationFailureHandler;
import s05t02.interactiveCV.service.security.authorization.AdminSpaceAuthorizationManager;
import s05t02.interactiveCV.service.security.authorization.UserSpaceAuthorizationManager;
import s05t02.interactiveCV.service.security.jwt.JwtCookieSecurityContextRepository;
import s05t02.interactiveCV.service.security.jwt.JwtCookieSuccessHandler;
import s05t02.interactiveCV.service.security.jwt.JwtLogoutSuccessHandler;

import java.util.List;


@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Value("${cookie.sameSite}")
    private String csrfSameSite;

    @Value("${cookie.secure}")
    private boolean csrfSecure;

    @Value("${app.frontend.origin}")
    private String frontendOrigin;

    @Value("${app.backend.origin}")
    private String backendOrigin;

    @Value("${app.dev-frontedn.origin")
    private String devFrontendOrigin;


    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                         JwtCookieSecurityContextRepository jwtCookieSecurityContextRepository,
                                                         JwtCookieSuccessHandler jwtSuccessHandler,
                                                         CustomReactiveAuthenticationFailureHandler failureHandler,
                                                         JwtLogoutSuccessHandler logoutSuccessHandler) {
        log.debug("Security filter chain initialized with JWT cookie support");
        return http
                .csrf(csrfSpec -> csrfSpec
                        .csrfTokenRepository(csrfTokenRepository())
                        .csrfTokenRequestHandler(doubleSubmitCsrfTokenHandler()))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .securityContextRepository(jwtCookieSecurityContextRepository)
                .formLogin(formLoginSpec -> formLoginSpec
                        .loginPage("/api/login")
                        .authenticationSuccessHandler(jwtSuccessHandler)
                        .authenticationFailureHandler(failureHandler)
                )
                .logout(logout -> logout
                        .logoutUrl("/api/logout")
                        .logoutSuccessHandler(logoutSuccessHandler))
                .exceptionHandling(exceptionHandlingSpec -> exceptionHandlingSpec
                        .authenticationEntryPoint(unauthorizedEntryPoint()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(ApiPaths.USER_BASE_PATH + "/**")
                        .access(userSpaceAuthManager())
                        .pathMatchers(ApiPaths.ADMIN_BASE_PATH)
                        .access(adminSpaceAuthManager())
                        .pathMatchers(ApiPaths.PROTECTED_BASE_PATH + "/**").authenticated()
                        .anyExchange().permitAll()
                )
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(frontendOrigin, devFrontendOrigin, backendOrigin));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("Authorization"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public ServerCsrfTokenRepository csrfTokenRepository() {
        CookieServerCsrfTokenRepository csrfTokenRepository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
        csrfTokenRepository.setCookieCustomizer(builder -> builder
                .sameSite(csrfSameSite)   // or "Lax", "None"
                .secure(csrfSecure)//
                .maxAge(3600)// important if using SameSite=None
                .path("/")            // optional, sets cookie path
        );
        return csrfTokenRepository;
    }

    @Bean
    public ReactiveAuthorizationManager<AuthorizationContext> userSpaceAuthManager() {
        return new UserSpaceAuthorizationManager();
    }

    @Bean
    public ReactiveAuthorizationManager<AuthorizationContext> adminSpaceAuthManager() {
        return new AdminSpaceAuthorizationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ServerCsrfTokenRequestHandler doubleSubmitCsrfTokenHandler() {
        return new ServerCsrfTokenRequestHandler() {

            @Override
            public void handle(ServerWebExchange exchange, Mono<CsrfToken> monoCsrf) {
                // Expose the CSRF token as an exchange attribute for controller access
                exchange.getAttributes().put(CsrfToken.class.getName(), monoCsrf);
            }

            @Override
            public Mono<String> resolveCsrfTokenValue(ServerWebExchange exchange, CsrfToken token) {
                // Read CSRF token from the X-XSRF-TOKEN header
                return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(token.getHeaderName()));
            }
        };
    }

    @Bean
    public WebFilter csrfLoggingFilter() {
        return (exchange, chain) -> {
            Mono<CsrfToken> csrfTokenMono = exchange.<Mono<CsrfToken>>getAttribute(CsrfToken.class.getName());
            if (csrfTokenMono != null) {
                return csrfTokenMono.doOnNext(token ->
                        System.out.println("Spring expects CSRF token: " + token.getToken())
                ).then(chain.filter(exchange));
            }
            return chain.filter(exchange);
        };
    }

    @Bean
    public ReactiveAuthenticationManager authenticationManager(
            ReactiveUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        UserDetailsRepositoryReactiveAuthenticationManager mgr =
                new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
        mgr.setPasswordEncoder(passwordEncoder);
        return mgr;
    }

    @Bean
    public ServerAuthenticationEntryPoint unauthorizedEntryPoint() {
        return (exchange, ex) -> {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        };
    }


}


