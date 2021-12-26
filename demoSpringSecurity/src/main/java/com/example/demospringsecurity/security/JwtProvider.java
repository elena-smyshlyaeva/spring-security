package com.example.demospringsecurity.security;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtProvider {

    private final UserDetailsService userDetailsService;

    @Autowired
    public JwtProvider(@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Value("${jwt.secret}") //определила заранее в application.properties
    private String secretKey = "secret-key";

    @Value("${jwt.expiration}")
    private Long validityMilliseconds;

    @Value("${jwt.header}")
    private String authorizationHeader;

    //для безопасности секретный ключ нужно зашифровать
    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    //создание токена
    public String createToken(String username, String role) {
        Claims claims = Jwts.claims().setSubject(username); //это полезные данные, которые хранятся внутри JWT
        claims.put("role", role); //как маппер, позволяет добавить в клеймс поле роль со значением роли

        //теперь нам нужно записать время, когда был создан токен
        Date now = new Date();

        //какое количество времени токен будет валидным
        //Date validity = new Date(now.getTime() + 100500 * 1000); //100500 миллисекунд (*1000, чтобы секунды получить) с создания токен будет действителен
        Date validity = new Date(now.getTime()+ validityMilliseconds * 1000);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now) //когда токен создан (issue - выпуск)
                .setExpiration(validity) //сколько валиден
                //.signWith(SignatureAlgorithm.HS256, "secret-key") //подписываем с помощью алгоритма широфания и секретного ключа
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();

        //время валидации токена и секретный ключ лучше вынести в переменные, которые будут определяться в
        //application properties
    }

    //проверка валидности (действительности) токена
    public boolean validateToken(String token) {
        try {
            //парсим переданный токен по секретному ключу
            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);

            //токен валидный, если время его валидации не истекло
            Date date = claimsJws.getBody().getExpiration();

            return !date.before(new Date()); //если дата валидации находится после текущей, то токен валидный
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtAuthenticationException("Jwt token is expired or invalid", HttpStatus.UNAUTHORIZED);
        }
    }

    //метод для получения аутентификации
    public Authentication getAuthentication(String token) {
        //аутентификация лежит в контексте, её необходимо оттуда достать
        //делается это с помощью UserDetailsService

        String username = getUsername(token);

        //находим пользователя и получаем его в виде имплиментации класса UserDetails
        //в данной программе эта имплиментация - securityUser
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

        //возвращаем аутентификацию
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());

    }

    //парсим из токена юзернейм, т.к. мы клали его в сабджект, то и возвращаем в сабджект
    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    //получение токена из http-запроса
    public String resolveToken(HttpServletRequest request) {
        return request.getHeader(authorizationHeader);
    }
}
