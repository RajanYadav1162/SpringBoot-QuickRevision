# Spring Security - Day-1

## Introduction & Default Configuration

### Default Spring Security Behavior
When Spring Security dependency is added to a Spring Boot project:
- **Automatic Configuration**: Spring Boot auto-configures security with default settings
- **Default Authentication Methods**:
    - HTTP Basic Authentication
    - Form-based Login
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

---

## Authentication vs Authorization

| **Authentication** | **Authorization** |
|-------------------|-------------------|
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

#### 1. **Authentication Filter**
- Intercepts requests and extracts authentication information
- Examples: `UsernamePasswordAuthenticationFilter`, `BasicAuthenticationFilter`

#### 2. **Authentication Manager**
- Central coordinator for authentication process
- Delegates actual authentication to Authentication Providers
- Default implementation: `ProviderManager`

#### 3. **Authentication Provider**
- Performs actual authentication logic
- Uses `UserDetailsService` and `PasswordEncoder`
- Can have multiple providers for different authentication methods

#### 4. **UserDetailsService**
- Loads user-specific data
- Core method: `loadUserByUsername(String username)`
- Returns `UserDetails` object

#### 5. **PasswordEncoder**
- Encodes passwords for storage
- Validates raw passwords against encoded ones
- **Never store plain text passwords in production!**

#### 6. **Security Context**
- Stores authentication information for the current thread
- Accessible via `SecurityContextHolder`

---

## Security Configuration

### Modern Configuration (Spring Security 5.7+)
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
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
            );
        
        return http.build();
    }
}
```

### Key Configuration Methods
- `authorizeHttpRequests()`: Configure authorization rules
- `httpBasic()`: Enable HTTP Basic authentication
- `formLogin()`: Enable form-based authentication
- `oauth2Login()`: Enable OAuth2 authentication
- `csrf()`: CSRF protection configuration
- `sessionManagement()`: Session management configuration

---

## UserDetailsService Implementation

### 1. In-Memory Implementation
```java
@Bean
public UserDetailsService userDetailsService() {
    UserDetails user = User.builder()
        .username("admin")
        .password(passwordEncoder().encode("password"))
        .roles("USER", "ADMIN")
        .authorities("read", "write")
        .accountExpired(false)
        .accountLocked(false)
        .credentialsExpired(false)
        .disabled(false)
        .build();

    return new InMemoryUserDetailsManager(user);
}
```

### 2. Database Implementation
```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        
        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password(user.getPassword())
            .authorities(user.getAuthorities())
            .build();
    }
}
```

### 3. LDAP Implementation
```java
@Bean
public UserDetailsService ldapUserDetailsService() {
    return new LdapUserDetailsManager(contextSource());
}
```

---

## Custom Authentication Provider

### Implementation Example
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

### When to Use Custom Authentication Provider
- **Custom authentication logic**: Integration with external systems
- **Multiple authentication methods**: Database + LDAP + OAuth
- **Additional validation**: Business rules, account status checks
- **Custom token types**: Beyond username/password authentication

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
| Encoder | Use Case | Security Level |
|---------|----------|----------------|
| `BCryptPasswordEncoder` | General purpose (recommended) | High |
| `SCryptPasswordEncoder` | High security applications | Very High |
| `Argon2PasswordEncoder` | Modern, memory-hard | Very High |
| `Pbkdf2PasswordEncoder` | Legacy systems | Medium |
| `NoOpPasswordEncoder` | **Testing only!** | None |

### Password Encoding Best Practices
```java
// Encoding passwords
String rawPassword = "userPassword";
String encodedPassword = passwordEncoder.encode(rawPassword);

// Validating passwords
boolean matches = passwordEncoder.matches(rawPassword, encodedPassword);
```

---

## HTTP Basic vs Form Login

### HTTP Basic Authentication
```java
// Configuration
http.httpBasic(Customizer.withDefaults());

// Usage with curl
curl -u username:password http://localhost:8080/api/data

// Or with Authorization header
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
    .defaultSuccessUrl("/dashboard")
    .failureUrl("/login?error")
    .permitAll()
);
```

**Characteristics:**
- Stateful (uses sessions)
- User-friendly login page
- Suitable for web applications
- Automatic CSRF protection
- Cookie-based session management

---

## Interview Questions & Key Points

### 🎯 Common Interview Questions

#### 1. **What is Spring Security and why use it?**
**Answer:** Spring Security is a comprehensive security framework for Java applications that provides:
- Authentication and authorization
- Protection against common vulnerabilities (CSRF, XSS, etc.)
- Integration with various authentication providers
- Declarative security configuration
- Method-level security

#### 2. **Explain the Spring Security architecture**
**Answer:** Spring Security follows a filter-based architecture:
- **Security Filter Chain**: Series of filters that process security concerns
- **Authentication Manager**: Coordinates authentication process
- **Authentication Provider**: Performs actual authentication
- **UserDetailsService**: Loads user information
- **Security Context**: Stores authentication information

#### 3. **What's the difference between authentication and authorization?**
**Answer:**
- **Authentication**: Verifying who the user is (identity verification)
- **Authorization**: Determining what the authenticated user can access (permission checking)

#### 4. **How do you configure method-level security?**
```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    // Configuration
}

@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(Long userId) {
    // Method implementation
}
```

#### 5. **What are the different types of password encoders?**
**Answer:** BCrypt, SCrypt, Argon2, PBKDF2, and NoOp (testing only). BCrypt is most commonly used in production.

#### 6. **How do you handle CORS in Spring Security?**
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

1. **Security First Principle**: Always consider security implications in design decisions
2. **HTTPS in Production**: Never use HTTP Basic auth without HTTPS
3. **Password Storage**: Never store plain text passwords
4. **CSRF Protection**: Understand when to enable/disable CSRF
5. **Session Management**: Know stateful vs stateless authentication
6. **Security Headers**: Understand security headers (X-Frame-Options, X-XSS-Protection, etc.)
