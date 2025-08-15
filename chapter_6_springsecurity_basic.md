# Spring Security - Comprehensive Study Notes


## Introduction & Default Configuration

### Default Spring Security Behavior
When Spring Security dependency is added to a Spring Boot project:

- **Automatic Configuration**: Spring Boot auto-configures security with default settings
- **Default Authentication Methods**: HTTP Basic Authentication and Form-based Login
- **Default User**: Creates a user with username `user` and a random password (printed in console)
- **All Endpoints Protected**: By default, all endpoints require authentication

### Key Default Components
```java
// Default security configuration includes:
// 1. HttpBasicConfigurer
// 2. FormLoginConfigurer  
// 3. DefaultLoginPageConfigurer
// 4. LogoutConfigurer
```

### Authentication vs Authorization

| Authentication | Authorization |
|----------------|---------------|
| Verifies WHO you are | Verifies WHAT you can do |
| Identity verification | Permission checking |
| Username + Password | Roles & Authorities |
| Happens first | Happens after authentication |

---

## Spring Security Architecture

### Security Filter Chain Flow
```
User Request → Security Filters → Authentication Filter → Authentication Manager → Authentication Provider → UserDetailsService + PasswordEncoder → Security Context
```

### Key Components Explained

#### 1. Authentication Filter
- Intercepts requests and extracts authentication information
- Examples: `UsernamePasswordAuthenticationFilter`, `BasicAuthenticationFilter`

#### 2. Authentication Manager
- Central coordinator for authentication process
- Delegates actual authentication to Authentication Providers
- Default implementation: `ProviderManager`

#### 3. Authentication Provider
- Performs actual authentication logic
- Uses UserDetailsService and PasswordEncoder
- Can have multiple providers for different authentication methods

#### 4. UserDetailsService
- Loads user-specific data
- Core method: `loadUserByUsername(String username)`
- Returns UserDetails object

#### 5. PasswordEncoder
- Encodes passwords for storage
- Validates raw passwords against encoded ones
- **Never store plain text passwords in production!**

#### 6. Security Context
- Stores authentication information for the current thread
- Accessible via `SecurityContextHolder`

---

## UserDetailsService vs UserDetailsManager

### UserDetailsService Contract
The `UserDetailsService` is the core interface for loading user data.

```java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

**Key Characteristics:**
- **Read-only operations**: Only loads user data
- **Single method**: `loadUserByUsername()`
- **Stateless**: No user management capabilities
- **Most common implementation**: Used in most applications

#### Custom UserDetailsService Implementation
```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        
        return User.builder()
            .username(user.getUsername())
            .password(user.getPassword())
            .authorities(user.getAuthority())
            .accountExpired(false)
            .accountLocked(false)
            .credentialsExpired(false)
            .disabled(false)
            .build();
    }
}
```

### UserDetailsManager Contract
The `UserDetailsManager` extends `UserDetailsService` and adds user management capabilities.

```java
public interface UserDetailsManager extends UserDetailsService {
    void createUser(UserDetails user);
    void updateUser(UserDetails user);
    void deleteUser(String username);
    void changePassword(String oldPassword, String newPassword);
    boolean userExists(String username);
}
```

**Key Characteristics:**
- **Full CRUD operations**: Create, Read, Update, Delete users
- **Password management**: Change password functionality
- **User existence checking**: `userExists()` method
- **Extends UserDetailsService**: Inherits `loadUserByUsername()`

### Built-in Implementations

#### 1. InMemoryUserDetailsManager
```java
@Bean
public UserDetailsManager userDetailsManager() {
    UserDetails user = User.builder()
        .username("admin")
        .password(passwordEncoder().encode("password"))
        .roles("USER", "ADMIN")
        .authorities("read", "write")
        .build();

    UserDetails user2 = User.builder()
        .username("user")
        .password(passwordEncoder().encode("userpass"))
        .roles("USER")
        .build();

    return new InMemoryUserDetailsManager(user, user2);
}
```

#### 2. JdbcUserDetailsManager
```java
@Bean
public UserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
    JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);
    
    // Custom queries (optional)
    manager.setUsersByUsernameQuery(
        "SELECT username, password, enabled FROM users WHERE username = ?"
    );
    manager.setAuthoritiesByUsernameQuery(
        "SELECT username, authority FROM authorities WHERE username = ?"
    );
    
    return manager;
}
```

**Required Database Schema for JdbcUserDetailsManager:**
```sql
CREATE TABLE users (
    username VARCHAR(50) NOT NULL PRIMARY KEY,
    password VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL
);

CREATE TABLE authorities (
    username VARCHAR(50) NOT NULL,
    authority VARCHAR(50) NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY (username) REFERENCES users(username)
);

CREATE UNIQUE INDEX ix_auth_username ON authorities (username, authority);
```

#### 3. LdapUserDetailsManager
```java
@Bean
public UserDetailsManager ldapUserDetailsManager() {
    LdapUserDetailsManager manager = new LdapUserDetailsManager(contextSource());
    manager.setUserDetailsMapper(new PersonContextMapper());
    return manager;
}

@Bean
public LdapContextSource contextSource() {
    LdapContextSource contextSource = new LdapContextSource();
    contextSource.setUrl("ldap://localhost:389");
    contextSource.setBase("dc=example,dc=com");
    contextSource.setUserDn("cn=admin,dc=example,dc=com");
    contextSource.setPassword("admin");
    return contextSource;
}
```

### When to Use Which?

| Scenario | Use |
|----------|-----|
| Simple authentication only | UserDetailsService |
| Need user management features | UserDetailsManager |
| Small, static user base | InMemoryUserDetailsManager |
| Database-backed users | JdbcUserDetailsManager |
| Enterprise LDAP integration | LdapUserDetailsManager |
| Complex custom logic | Custom UserDetailsService |

---

## Authentication Providers

### Custom Authentication Provider
```java
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        try {
            UserDetails user = userDetailsService.loadUserByUsername(username);
            
            // Custom validation logic can be added here
            if (!user.isEnabled()) {
                throw new DisabledException("User account is disabled");
            }
            
            if (!user.isAccountNonLocked()) {
                throw new LockedException("User account is locked");
            }
            
            if (passwordEncoder.matches(password, user.getPassword())) {
                return new UsernamePasswordAuthenticationToken(
                    username, 
                    password, 
                    user.getAuthorities()
                );
            } else {
                throw new BadCredentialsException("Invalid credentials");
            }
        } catch (UsernameNotFoundException e) {
            throw new BadCredentialsException("User not found");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```

### Multiple Authentication Providers
```java
@Configuration
public class SecurityConfig {
    
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config,
            CustomAuthenticationProvider customProvider,
            DaoAuthenticationProvider daoProvider) throws Exception {
        
        List<AuthenticationProvider> providers = Arrays.asList(
            customProvider,
            daoProvider
        );
        
        ProviderManager providerManager = new ProviderManager(providers);
        return providerManager;
    }
}
```

---

## Password Encoders

### Production-Ready Encoders
```java
@Bean
public PasswordEncoder passwordEncoder() {
    // BCrypt (Recommended for most cases)
    return new BCryptPasswordEncoder(12); // strength 12
    
    // Or use Spring Security's delegating encoder
    // return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
```

### Available Encoders

| Encoder | Use Case | Security Level | Performance |
|---------|----------|----------------|-------------|
| `BCryptPasswordEncoder` | General purpose (recommended) | High | Good |
| `SCryptPasswordEncoder` | High security applications | Very High | Slower |
| `Argon2PasswordEncoder` | Modern, memory-hard | Very High | Slower |
| `Pbkdf2PasswordEncoder` | Legacy systems | Medium | Fast |
| `NoOpPasswordEncoder` | **Testing only!** | None | Fastest |

### Delegating Password Encoder
```java
@Bean
public PasswordEncoder passwordEncoder() {
    // Supports multiple encoding formats
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}

// Encoded passwords will have prefixes like:
// {bcrypt}$2a$10$dXJ3SW6G7P90lGRkRcLvLuHBHo7ClNxvwsDnCsOvhj7Q5CxE1BVQi
// {scrypt}$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7rBEqQ=
```

### Password Encoding Best Practices
```java
// Encoding passwords
String rawPassword = "userPassword";
String encodedPassword = passwordEncoder.encode(rawPassword);

// Validating passwords  
boolean matches = passwordEncoder.matches(rawPassword, encodedPassword);

// Migration strategy for existing plain text passwords
@Component
public class PasswordMigrationService {
    
    public void migratePassword(String username, String plainPassword) {
        if (isPlainTextPassword(plainPassword)) {
            String encodedPassword = passwordEncoder.encode(plainPassword);
            userRepository.updatePassword(username, encodedPassword);
        }
    }
    
    private boolean isPlainTextPassword(String password) {
        return !password.startsWith("{") || password.startsWith("{noop}");
    }
}
```

---

## Authentication Methods

### HTTP Basic Authentication
```java
// Configuration
http.httpBasic(Customizer.withDefaults());

// Custom configuration
http.httpBasic(basic -> basic
    .realmName("My Application")
    .authenticationEntryPoint(customAuthenticationEntryPoint())
);
```

**Usage Examples:**
```bash
# With curl
curl -u username:password http://localhost:8080/api/data

# Or with Authorization header
curl -H "Authorization: Basic <Base64(username:password)>" http://localhost:8080/api/data
```

**Characteristics:**
- Stateless
- Credentials sent with every request
- Suitable for APIs
- Base64 encoded (not encrypted)
- **Must use HTTPS in production**

### Form Login Authentication
```java
// Configuration
http.formLogin(form -> form
    .loginPage("/login")
    .loginProcessingUrl("/authenticate")
    .defaultSuccessUrl("/dashboard")
    .failureUrl("/login?error")
    .usernameParameter("email") // default is "username"
    .passwordParameter("pass")  // default is "password"
    .successHandler(customSuccessHandler())
    .failureHandler(customFailureHandler())
    .permitAll()
);
```

**Custom Success Handler:**
```java
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
                                      HttpServletResponse response,
                                      Authentication authentication) throws IOException {
        
        String targetUrl = determineTargetUrl(authentication);
        response.sendRedirect(targetUrl);
    }
    
    private String determineTargetUrl(Authentication authentication) {
        boolean isAdmin = authentication.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        
        return isAdmin ? "/admin/dashboard" : "/user/dashboard";
    }
}
```

**Characteristics:**
- Stateful (uses sessions)
- User-friendly login page
- Suitable for web applications
- Automatic CSRF protection
- Cookie-based session management

---

## Authorization & Method Security

### URL-Based Authorization
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authz -> authz
        // Public endpoints
        .requestMatchers("/public/**", "/css/**", "/js/**").permitAll()
        .requestMatchers("/login", "/register").permitAll()
        
        // Role-based access
        .requestMatchers("/admin/**").hasRole("ADMIN")
        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
        
        // Authority-based access
        .requestMatchers(HttpMethod.DELETE, "/api/**").hasAuthority("DELETE")
        .requestMatchers("/api/sensitive/**").hasAuthority("SENSITIVE_READ")
        
        // Custom expression
        .requestMatchers("/profile/**").access(new WebExpressionAuthorizationManager(
            "hasRole('USER') and @userService.isOwner(authentication.name, request)"
        ))
        
        // Default - all other requests need authentication
        .anyRequest().authenticated()
    );
    
    return http.build();
}
```

### Method-Level Security
```java
@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class MethodSecurityConfig {
    // Configuration
}

@Service
public class UserService {
    
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(Long userId) {
        // Only ADMIN can delete users
    }
    
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
    public User getProfile(String username) {
        // Users can only access their own profile
    }
    
    @PostAuthorize("returnObject.owner == authentication.name")
    public Document getDocument(Long documentId) {
        // User can only access documents they own
    }
    
    @Secured({"ROLE_ADMIN", "ROLE_MANAGER"})
    public void approveRequest(Long requestId) {
        // ADMIN or MANAGER can approve
    }
    
    @RolesAllowed("ADMIN")
    public void systemConfiguration() {
        // JSR-250 annotation
    }
}
```

### Custom Security Expressions
```java
@Component("userSecurity")
public class UserSecurity {
    
    public boolean isOwner(Authentication authentication, Long userId) {
        String username = authentication.getName();
        // Custom logic to check ownership
        return userService.isUserOwner(username, userId);
    }
    
    public boolean hasPermission(Authentication authentication, String permission) {
        return authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals(permission));
    }
}

// Usage in controller
@PreAuthorize("@userSecurity.isOwner(authentication, #userId)")
@GetMapping("/users/{userId}")
public User getUser(@PathVariable Long userId) {
    return userService.findById(userId);
}
```

---

## Security Configuration

### Modern Configuration (Spring Security 6+)
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers("/api/public/**")
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
                .sessionRegistry(sessionRegistry())
            )
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .httpBasic(Customizer.withDefaults())
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/login?logout")
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
            )
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(customAuthenticationEntryPoint())
                .accessDeniedHandler(customAccessDeniedHandler())
            );
        
        return http.build();
    }
}
```

### CORS Configuration
```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOriginPatterns(Arrays.asList("http://localhost:*"));
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(Arrays.asList("*"));
    configuration.setAllowCredentials(true);
    configuration.setExposedHeaders(Arrays.asList("Authorization"));
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

---

## Advanced Concepts

### JWT Authentication
```java
@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {
    
    @Autowired
    private JwtService jwtService;
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = (String) authentication.getCredentials();
        
        if (jwtService.validateToken(token)) {
            String username = jwtService.extractUsername(token);
            List<GrantedAuthority> authorities = jwtService.extractAuthorities(token);
            
            return new UsernamePasswordAuthenticationToken(username, token, authorities);
        }
        
        throw new BadCredentialsException("Invalid JWT token");
    }
    
    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```

### Remember Me Configuration
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .rememberMe(remember -> remember
            .key("uniqueAndSecret")
            .tokenValiditySeconds(86400) // 24 hours
            .userDetailsService(userDetailsService())
            .tokenRepository(persistentTokenRepository())
        );
    
    return http.build();
}

@Bean
public PersistentTokenRepository persistentTokenRepository() {
    JdbcTokenRepositoryImpl tokenRepo = new JdbcTokenRepositoryImpl();
    tokenRepo.setDataSource(dataSource);
    return tokenRepo;
}
```

### Event Handling
```java
@Component
public class AuthenticationEventListener {
    
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        log.info("User {} logged in successfully", username);
        // Update last login time, log audit trail, etc.
    }
    
    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        String username = event.getAuthentication().getName();
        log.warn("Login failed for user {}: {}", username, event.getException().getMessage());
        // Implement account lockout logic, send alerts, etc.
    }
}
```

---

## Best Practices & Common Pitfalls

### ✅ Best Practices

1. **Always use HTTPS in production**
   ```yaml
   server:
     ssl:
       enabled: true
   ```

2. **Implement proper password policies**
   ```java
   @Component
   public class PasswordValidator {
       public boolean isValid(String password) {
           return password.length() >= 8 &&
                  password.matches(".*[A-Z].*") &&
                  password.matches(".*[a-z].*") &&
                  password.matches(".*\\d.*") &&
                  password.matches(".*[!@#$%^&*()].*");
       }
   }
   ```

3. **Handle exceptions properly**
   ```java
   @ControllerAdvice
   public class SecurityExceptionHandler {
       
       @ExceptionHandler(AuthenticationException.class)
       public ResponseEntity<ErrorResponse> handleAuthenticationException(
               AuthenticationException ex) {
           
           return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
               .body(new ErrorResponse("Authentication failed", ex.getMessage()));
       }
   }
   ```

### ❌ Common Pitfalls

1. **Using NoOpPasswordEncoder in production**
   ```java
   // DON'T DO THIS IN PRODUCTION!
   @Bean
   public PasswordEncoder passwordEncoder() {
       return NoOpPasswordEncoder.getInstance();
   }
   ```

2. **Exposing sensitive information in error messages**
   ```java
   // Bad - reveals if user exists
   throw new BadCredentialsException("User " + username + " not found");
   
   // Good - generic message
   throw new BadCredentialsException("Invalid credentials");
   ```

3. **Not configuring session management**
   ```java
   // Configure session management properly
   .sessionManagement(session -> session
       .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
       .maximumSessions(1)
       .sessionFixation().migrateSession()
   )
   ```

---

## Interview Questions

### 🎯 Common Interview Questions

**1. What is Spring Security and why use it?**

Spring Security is a comprehensive security framework for Java applications that provides:
- Authentication and authorization
- Protection against common vulnerabilities (CSRF, XSS, etc.)
- Integration with various authentication providers
- Declarative security configuration
- Method-level security

**2. Explain the difference between UserDetailsService and UserDetailsManager**

- **UserDetailsService**: Read-only interface with single method `loadUserByUsername()`
- **UserDetailsManager**: Extends UserDetailsService, adds CRUD operations for user management
- Use UserDetailsService for authentication-only scenarios
- Use UserDetailsManager when you need full user management capabilities

**3. What are the different types of password encoders?**

- **BCryptPasswordEncoder**: Most commonly used, good balance of security and performance
- **SCryptPasswordEncoder**: Higher security, slower performance
- **Argon2PasswordEncoder**: Modern, memory-hard function
- **Pbkdf2PasswordEncoder**: Legacy support
- **NoOpPasswordEncoder**: Testing only, never use in production

**4. How do you implement method-level security?**

```java
@EnableMethodSecurity(prePostEnabled = true)
@Configuration
public class MethodSecurityConfig {}

@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(Long userId) {
    // Implementation
}
```

**5. Explain the Security Filter Chain**

The Security Filter Chain is a series of filters that process security concerns:
1. Security Context Persistence Filter
2. Authentication Filter
3. Session Management Filter
4. Exception Translation Filter
5. Filter Security Interceptor

**6. How do you handle CORS in Spring Security?**

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
    configuration.setAllowCredentials(true);
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

### 🔑 Key Points for Interviews

- **Security First Principle**: Always consider security implications in design decisions
- **HTTPS in Production**: Never use HTTP Basic auth without HTTPS
- **Password Storage**: Never store plain text passwords
- **CSRF Protection**: Understand when to enable/disable CSRF
- **Session Management**: Know stateful vs stateless authentication
- **Role vs Authority**: Roles are authorities with "ROLE_" prefix
- **Exception Handling**: Proper security exception handling prevents information leakage
