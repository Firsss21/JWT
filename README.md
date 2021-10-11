## JSON Web Token (JWT)

### Содержание:

+ [Описание JWT](#описание-jwt)
+ [Структура JWT](#структура-jwt) 
+ [Как JWT защищает наши данные?](#как-jwt-защищает-наши-данные)
+ [Пример использования JWT в Spring Security](#пример-использования-jwt-в-spring-security)
+ [Источники](#источники)

### Описание JWT

**JWT** - стандарт, для создания токенов доступа, основанный на формате **JSON**. Используется для передачи данных для аутентификации. Токены создаются **сервером**, подписываются секретным ключом и передаются **клиенту**, который использует его для подтверждения своей личности

**JSON объект**, который определен в открытом стандарте **RFC 7519**. Он считается одним из безопасных способов передачи информации между двумя участниками. Для его создания необходимо определить заголовок (header) с общей информацией по токену, полезные данные (payload), такие как id пользователя, его роль и т.д. и подписи (signature). 

Простыми словами, **JWT** — это лишь зашифрованная JSON строка в следующем формате `header.payload.signature`.

Области применения **JWT**:
- **Микросервисы.** Данные формируются и подписываются на одном микросервисе, а используются на другом микросервисе, который проверяет подпись токена публичным ключом.

- **Авторизация.** Этот кейс может быть полезен и для монолита, если нужно сократить количество запросов в базу данных. При реализации "традиционной" сессии каждый запрос API генерирует дополнительный запрос профайла пользователя к базе данных. С JWT все, что берется в базе данных — помещается в JWT и подписывается.

Приложение использует **JWT** для проверки аутентификации пользователя следующим образом:

![image](https://user-images.githubusercontent.com/47852430/136719802-ccbb10d6-db9d-46fc-87d2-26b6722ba789.png)

- Пользователь заходит на сервер аутентификации с помощью **аутентификационного ключа**.
- Сервер аутентификации создает **JWT** и отправляет его пользователю.
- При запросе пользователь добавляет к нему полученный ранее JWT.
- Приложение проверяет по переданному с запросом **JWT** является ли пользователь тем, за кого себя выдает.

### Структура JWT

<i>JWT</i> состоит из трех частей: заголовок `header`, полезные данные `payload` и подпись `signature`.

![image](https://user-images.githubusercontent.com/47852430/135950774-7818be39-b854-4536-9b6a-f9e77885df8a.png)

Хэдер <i>JWT</i> содержит информацию  том, как должна вычисляться <i>JWT</i> подпись. Хэдер - это <i>JSON</i> объект, который выглядит следующим образом:

```java
header = { "alg": "HS256", "typ": "JWT"}
```
Поле `typ` только показывает, что это <i>JWT</i>, поле `alg` уже определяет алгоритм хеширования. Будет использоваться при создании подписи.

Поле <i>Payload</i> хранит в себе полезные данные, которые хранятся внутри <i>JWT</i>. Эти данные называют так же <i>JWT-claims(заявки)</i>. Пример payload, где токен хранит в себе <i>id</i> пользователя.

```java
payload = {"userId": "b08f86af-35da-48f2-8fab-cef3904660bd" }
```
Мы положили только одну <i>заявку</i>(claim) в <i>payload</i>. Вы можете положитьь столько заявок, сколько захотите. 
Существует список стандартных <i>заявок</i> для <i>JWT payload</i>:

- iss (issuer) - определяет приложение, из которого отправляется токен.
- sub (subject) - определяет тему токена.
- exp (expiration time) - время жизни токена.

**Создаем Signature** (пример на псевдокоде).

```java
const SECRET_KEY = 'cAtwa1kkEy'
const unsignedToken = base64urlEncode(header) + '.' + base64urlEncode(payload)
const signature = HMAC-SHA256(unsignedToken, SECRET_KEY)
```
Алгоритм **base64url** кодирует <i>хедер</i> и <i>payload</i>, созданные раннее. Алгоритм соединяет закодированные строки через точку, затем строка хешируется алгоритмом, заданным в хедере на основе нашего секретного ключа, что бы далее мы могли расшифровать токен.

```
header eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
 payload eyJ1c2VySWQiOiJiMDhmODZhZi0zNWRhLTQ4ZjItOGZhYi1jZWYzOTA0NjYwYmQifQ
 signature -xN_h82PHVTCMA9vdoHrcZxH-x5mb11y1537t3rGzcM
```

Далее объеденяем все три **JWT компонента** вместе, просто соединяем полученные элементы через точку.

```java
const token = encodeBase64Url(header) + '.' + encodeBase64Url(payload) + '.' + encodeBase64Url(signature)
// JWT Token
// eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOiJiMDhmODZhZi0zNWRhLTQ4ZjItOGZhYi1jZWYzOTA0NjYwYmQifQ.-xN_h82PHVTCMA9vdoHrcZxH-x5mb11y1537t3rGzcM
```

Далее можно пользоваться этим токеном, наш сервер авторизации сможет проверить токен с помощью оставшегося у него **секрета*.

### Как JWT защищает наши данные?

Использование <i>JWT</i> **НЕ СКРЫВАЕТ** и **НЕ МАСКИРУЕТ** данные автоматически. Причина использования <i>JWT</i> - проверка, что отправленные данные были действительно отправлены авторизованным источником.

Данные внутри <i>JWT</i> закодированы и подписаны, а это не тоже самое, что зашифрованы. Кодирование - используется для преобразования структуры, подпись - для аутентификации, т.е. не защищают данные, когда главная цель шифрования - защита данных от неавторизированного доступа.

Поскольку <i>JWT</i> только лишь закодирована и подписана и поскольку <i>JWT</i> не зашифрована, <i>JWT</i> не гарантирует никакой безопасности для чувствительных (<i>sensitive</i>) данных.

### Пример использования JWT в Spring Security

Наш `SecurityConfig`, который конфигурирует такие вещи, как:
- `passwordEncoder` для паролей наших пользователей
- Отключает csrf
- Определяет доступные пользователю пути без авторизации
- Определяет доступные пользователю данные в зависимости от его уровня доступа
- Добавляет фильтр для аутентификации пользователя
- Добавляет фильтр для авторизации пользователя через <i>JWT token</i>

```java
@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter caf = new CustomAuthenticationFilter(authenticationManagerBean());
        caf.setFilterProcessesUrl("/api/login");
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests().antMatchers("/api/login/**", "/api/refreshToken/**").permitAll();
        http.authorizeRequests().antMatchers(GET, "/api/user/**").hasAnyAuthority("ROLE_USER");
        http.authorizeRequests().antMatchers(POST, "/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(caf);
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```
`CustomAuthenticationFilter`, в котором мы аутентифицируем пользователя и создаем новые **JWT токены**, такие как **access token** и  **refresh token**, которые после ему отправляем

```java
@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is: {}", username);
        log.info("Password is: {}", password);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        User user = (User) authentication.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(e -> e.getAuthority()).collect(Collectors.toList()))
                .sign(algorithm);
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }
}
```

`CustomAuthorizationFilter` фильтр, в котором мы авторизируем пользователя через его **JWT token** на каждый его запрос к <i>API</i>

```java
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/refreshToken")) {
            filterChain.doFilter(request, response);
        } else {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                try {
                    String token = authorizationHeader.substring("Bearer ".length());

                    Algorithm alg = Algorithm.HMAC256("secret".getBytes());
                    JWTVerifier verifier = JWT.require(alg).build();

                    DecodedJWT decodedJWT = verifier.verify(token);
                    String userName = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<SimpleGrantedAuthority> authorityCollection = new ArrayList<>();
                    Arrays.stream(roles).forEach(e -> authorityCollection.add(new SimpleGrantedAuthority(e)));

                    UsernamePasswordAuthenticationToken upat = new UsernamePasswordAuthenticationToken(userName, null, authorityCollection);
                    SecurityContextHolder.getContext().setAuthentication(upat);
                    filterChain.doFilter(request, response);
                } catch (Exception e) {
                    log.error("Error logging in: {} ", e.getMessage());
                    response.setHeader("error", e.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    HashMap<String, String> error = new HashMap<>();
                    error.put("error_message", e.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }
}

```

<i>Refresh token</i>. Эндпоинт для получения нового ключа при инвалидации старого с помощью `refresh token`.

```java
    @PostMapping("/refreshToken/")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = request.getHeader(AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                String refreshToken = authHeader.substring("Bearer ".length());

                Algorithm alg = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verifier = JWT.require(alg).build();

                DecodedJWT decodedJWT = verifier.verify(refreshToken);
                String userName = decodedJWT.getSubject();

                User user = userService.getUser(userName);
                String accessToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(alg);

                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", accessToken);
                tokens.put("refresh_token", refreshToken);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            } catch (Exception e) {
                response.setHeader("error", e.getMessage());
                response.setStatus(FORBIDDEN.value());
                HashMap<String, String> error = new HashMap<>();
                error.put("error_message", e.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }
```
### Источники

- https://habr.com/ru/post/340146/
- https://habr.com/ru/post/532130/
- https://jwt.io/
- https://en.wikipedia.org/wiki/JSON_Web_Token
