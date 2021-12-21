package com.example.demospringsecurity.config;

import com.example.demospringsecurity.domain.Permission;
import com.example.demospringsecurity.domain.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()

                .authorizeRequests()    //авторизация запроса (определение его прав доступа)
                .antMatchers("/")   //какие паттерны урлов имеется доступ
                .permitAll()   //доступ к главной странице ("/") есть у всех

                /*
                авторизация на основании ролей

                //http-метод GET, который будет отправлен на любую страницу с урлом /api/... ,
                //будет доступен всем: админу и обычному пользователю
                .antMatchers(HttpMethod.GET, "/api/**").hasAnyRole(Role.ADMIN.name(), Role.USER.name())

                //если метод POST, то доступ имеется только у админа
                .antMatchers(HttpMethod.POST, "/api/**").hasRole(Role.ADMIN.name())

                //аналогично для delete метода
                .antMatchers(HttpMethod.DELETE, "/api/**").hasRole(Role.ADMIN.name())

                 */

                /*
                авторизация на основании ращрешений
                 */
                .antMatchers(HttpMethod.GET,"/api/**").hasAuthority(Permission.DEVELOPERS_READ.getPermission())
                .antMatchers(HttpMethod.POST, "/api/**").hasAuthority(Permission.DEVELOPERS_WRITE.getPermission())
                .antMatchers(HttpMethod.DELETE, "/api/**").hasAuthority(Permission.DEVELOPERS_WRITE.getPermission())

                //любой запрос должен быть аутентифицирован (с помощью 64basic)
                .anyRequest().authenticated().and().httpBasic();
    }

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("1234"))
                        //.roles(Role.ADMIN.name())
                        .authorities(Role.ADMIN.getAuthorities())
                        .build(),
                User.builder()
                        .username("user1")
                        .password(passwordEncoder().encode("1111"))
                        //.roles(Role.USER.name())
                        .authorities(Role.USER.getAuthorities())
                        .build()
        );
    }

    //bean for encrypt password
    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
