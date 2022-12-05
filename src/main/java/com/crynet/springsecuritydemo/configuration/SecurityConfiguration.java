package com.crynet.springsecuritydemo.configuration;

import com.crynet.springsecuritydemo.security.CustomLoginConfigurer;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfiguration {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Bean
    SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());
        http.apply(new CustomLoginConfigurer<>())
                .loginProcessingUrl("/api/login")
                .successHandler((request, response, authentication) -> {
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().print(objectMapper.writeValueAsString(authentication.getPrincipal()));
                })
                .failureHandler((request, response, exception) -> response.setStatus(HttpServletResponse.SC_BAD_REQUEST));
        http.logout()
                .logoutUrl("/api/logout")
                .logoutSuccessHandler((request, response, authentication) -> response.setStatus(HttpServletResponse.SC_OK))
                .deleteCookies("QBASIC_SESSION_ID");
        http.exceptionHandling()
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
        return http.build();
    }

}
