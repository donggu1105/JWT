package com.example.jwt.config;

import com.example.jwt.config.oauth.*;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    private final CustomUserDetailsService customUserDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;


    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }

    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieOAuth2AuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // jwt filter
        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        // jwt ?????? ???????????? ??????
        http.cors()
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .exceptionHandling().authenticationEntryPoint(new RestAuthenticationEntryPoint()); // ??????,????????? ?????? ?????? ?????? ??? ??????

        // ?????? ??????
        http.authorizeRequests()
                .antMatchers("/", "/oauth2/**", "/auth/**").permitAll()
                .antMatchers("/api/v1/user").hasAnyRole()
                .antMatchers("/api/v1/admin").hasRole(Role.ADMIN.toString())
                .anyRequest().authenticated();

        // OAuth2 ????????? ?????? ??????
        http.oauth2Login()
            .authorizationEndpoint().baseUri("/oauth2/authorization") // ?????? ????????? Url
            .authorizationRequestRepository(cookieOAuth2AuthorizationRequestRepository()) // ?????? ????????? ????????? ???????????? ??????
            .and()
            .redirectionEndpoint().baseUri("/oauth2/callback/*") // ?????? ?????? ??? Redirect Url
            .and()
            .userInfoEndpoint().userService(customOAuth2UserService) // ????????? ?????? ????????? ????????? ????????????
            .and()
            .successHandler(oAuth2AuthenticationSuccessHandler) // ?????? ?????? ??? Handler
            .failureHandler(oAuth2AuthenticationFailureHandler); // ?????? ?????? ??? Handler

    }
}
