# Spring Security Authentication Learning Notes

This document summarizes key concepts from learning Spring Security authentication, based on provided notes. It has been organized for clarity, corrected for typos, enhanced with additional details for better understanding, and includes important concepts related to authentication flows, such as the role of `AuthenticationManager`, common exceptions, and best practices.

***

## 1. Basics of Spring Security Authentication

Spring Security provides a robust framework for handling authentication and authorization in Java applications. **Authentication** verifies who the user is, while **authorization** determines what they can access.

* **SecurityContext**: This is a central component that holds authentication-related data for the current user (or thread). It acts as a container for the `Authentication` object after a successful login. You can access it via `SecurityContextHolder.getContext()`.
    * **Key methods**: `getAuthentication()` to retrieve the current user's authentication details and `setAuthentication(Authentication auth)` to store it after successful authentication.
    * **Why it's important**: It ensures that user details are available throughout the request lifecycle without needing to re-authenticate.

* **Principal Interface**: Represents the identity of the authenticated user. In Spring, the `Authentication` interface extends `Principal`, providing a unified way to access user info.
    * **Common implementations**: `UserDetails` (from `UserDetailsService`) or custom tokens.

* **Added Concept**: Spring Security uses a **filter chain** (e.g., `SecurityFilterChain`) to handle security. Filters like `UsernamePasswordAuthenticationFilter` or custom ones process incoming requests for authentication.

***

## 2. Key Interfaces and Classes

### Authentication Interface

Extends `Principal`.
* **Key methods**:
    * `getCredentials()`: Returns credentials like a password, token, or fingerprint (often cleared after authentication for security).
    * `getAuthorities()`: Returns a collection of `GrantedAuthority` objects (e.g., roles like "ROLE_USER").
    * `getDetails()`: Additional user details (e.g., IP address, session info).
    * `getPrincipal()`: The user identity (e.g., username or `UserDetails` object).
    * `isAuthenticated()`: A boolean indicating if authentication was successful.

> After successful authentication, Spring clears sensitive data like passwords from the `Authentication` object to protect user privacy.

### AuthenticationProvider Interface

Responsible for performing the actual authentication logic.
* **Key method**: `Authentication authenticate(Authentication authentication)`.
    * **Input**: An unauthenticated `Authentication` object (e.g., `UsernamePasswordAuthenticationToken` with username and password).
    * **Logic**: Validate credentials (e.g., check against a database).
    * **Output**:
        * **On success**: Return a fully populated, authenticated `Authentication` object.
        * **On failure**: Throw an `AuthenticationException` (e.g., `BadCredentialsException` for an invalid password).
        * **If unsupported**: Return `null` (allows chaining to the next provider).
* `supports()` **Method**: `boolean supports(Class<?> authentication)` – Checks if this provider can handle the given authentication type.

### AuthenticationManager

* **Added Concept (Missing in Notes)**: This is the orchestrator that delegates to one or more `AuthenticationProvider` instances. It tries providers in order until one succeeds or all fail.
* **Common implementation**: `ProviderManager`.
* In multi-provider setups, it's configured with a list of providers (e.g., a custom token provider + a DAO provider for username/password).

### Common Exceptions (Enhanced)

* `AuthenticationException`: Base class for all authentication failures.
* **Subclasses**: `BadCredentialsException` (invalid credentials), `UsernameNotFoundException` (user not found), `AccountExpiredException`, etc.
* Always handle these gracefully in custom providers to avoid exposing sensitive information.

***

## 3. Authentication Process Flow

1.  **Request Arrival**: A filter (e.g., custom or `BasicAuthenticationFilter`) extracts credentials from the request (headers, form data, etc.).
2.  **Create Token**: Build an unauthenticated `Authentication` token (e.g., `UsernamePasswordAuthenticationToken`).
3.  **Authenticate**: Pass the token to `AuthenticationManager`, which delegates to providers.
4.  **Provider Logic**:
    * Validate credentials.
    * If valid, create an authenticated token with authorities.
    * Clear sensitive data (e.g., password).
5.  **Store in Context**: On success, set the authenticated `Authentication` in `SecurityContextHolder.getContext().setAuthentication(auth)`.
6.  **Fallback**: If one provider fails or returns `null`, try the next (e.g., magic header → basic auth).
7.  **Access Control**: Use the stored context for authorization (e.g., `@PreAuthorize` annotations or `.authorizeHttpRequests()`).

* **Best Practice**: Use HTTPS to protect credentials in transit. Enable CSRF protection for form-based auth (via `.csrf(Customizer.withDefaults())`).

***

## 4. Custom Authentication with Multiple Providers

Spring allows chaining multiple `AuthenticationProvider` for different auth mechanisms (e.g., header-based + username/password).

* **Example Scenario**: A "magic header" for API auth, falling back to HTTP Basic.
* **Key Components**:
    * **Custom Token**: Extend `UsernamePasswordAuthenticationToken` (e.g., `MagicHeaderAuthenticationToken`).
    * **Custom Provider**: Implement `AuthenticationProvider` to validate the header.
    * **Custom Filter**: Extend `OncePerRequestFilter` to extract the header, create the token, and authenticate.
    * **Configuration**: Add the filter before others (e.g., `.addFilterBefore(...)`), and configure `AuthenticationManager` with the providers.

### Code Example

Below is the provided code, cleaned up and commented for clarity. It demonstrates a Spring Boot app with multi-provider auth.

```java
package com.rajan.springbootrecipies;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

@SpringBootApplication
public class SpringbootrecipiesApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringbootrecipiesApplication.class, args);
    }
}

@Configuration
class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Add custom filter BEFORE basic auth filter
                .addFilterBefore(magicHeaderAuthenticationFilter(), BasicAuthenticationFilter.class)
                // Enable HTTP Basic as fallback
                .httpBasic(Customizer.withDefaults())
                // Require auth for all requests
                .authorizeHttpRequests(req -> req.anyRequest().authenticated())
                // Use multi-provider manager
                .authenticationManager(authenticationManager());
        return http.build();
    }

    @Bean
    public MagicHeaderAuthenticationFilter magicHeaderAuthenticationFilter() {
        return new MagicHeaderAuthenticationFilter();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(Arrays.asList(
                magicHeaderAuthenticationProvider(),
                daoAuthenticationProvider()
        ));
    }

    @Bean
    public MagicHeaderAuthenticationProvider magicHeaderAuthenticationProvider() {
        return new MagicHeaderAuthenticationProvider();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withUsername("root")
                        .password("root")
                        .authorities("admin")
                        .build());
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); // Note: Use a real encoder like BCrypt in production!
    }
}

// Custom Token for Magic Header
class MagicHeaderAuthenticationToken extends UsernamePasswordAuthenticationToken {
    public MagicHeaderAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public MagicHeaderAuthenticationToken(Object principal, Object credentials,
                                          java.util.Collection<? extends org.springframework.security.core.GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}

// Custom Provider for Magic Header
class MagicHeaderAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String magicValue = (String) authentication.getCredentials();
        if ("magic".equals(magicValue)) {
            return new MagicHeaderAuthenticationToken(
                    "magic-user", magicValue,
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_MAGIC"))
            );
        } else {
            throw new BadCredentialsException("Invalid magic header value!");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MagicHeaderAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

// Custom Filter to Extract Magic Header
class MagicHeaderAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Skip if already authenticated
        if (SecurityContextHolder.getContext().getAuthentication() != null &&
                SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract header
        String magicHeader = request.getHeader("X-Magic-Header");
        if (magicHeader != null) {
            try {
                MagicHeaderAuthenticationToken authToken = new MagicHeaderAuthenticationToken("magic-user", magicHeader);
                AuthenticationManager authManager = getAuthenticationManager(); // Retrieve from context
                Authentication authenticatedToken = authManager.authenticate(authToken);
                SecurityContextHolder.getContext().setAuthentication(authenticatedToken);
                System.out.println("Magic header authentication successful for: " + authenticatedToken.getName());
            } catch (AuthenticationException e) {
                System.out.println("Magic header authentication failed: " + e.getMessage());
                // Fall through to next auth (e.g., basic)
            }
        }
        filterChain.doFilter(request, response);
    }

    // Helper to get AuthenticationManager
    private AuthenticationManager getAuthenticationManager() {
        return org.springframework.web.context.support.WebApplicationContextUtils
                .getRequiredWebApplicationContext(getServletContext())
                .getBean(AuthenticationManager.class);
    }
}

@RestController
class GreetController {

    @GetMapping("/greet")
    public String greet() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        String authorities = auth.getAuthorities().toString();
        return String.format("Hello %s! Your authorities: %s", username, authorities);
    }

    @GetMapping("/secure")
    public String secure() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Secure endpoint accessed by: " + auth.getName() + " with authorities: " + auth.getAuthorities();
    }
}

// Alternative Simpler Filter (No Separate Provider)
class SimpleMagicHeaderFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() != null &&
                SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        String magicHeader = request.getHeader("X-Magic-Header");
        if (magicHeader != null && "magic".equals(magicHeader)) {
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    "magic-user", null,
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_MAGIC"))
            );
            SecurityContextHolder.getContext().setAuthentication(authToken);
            System.out.println("Magic header authentication successful!");
        }
        filterChain.doFilter(request, response);
    }
}
```

## Notes on Code
- Uses `InMemoryUserDetailsManager` for demo purposes; in production, prefer JDBC, JPA, or LDAP for persistent user storage.
- `NoOpPasswordEncoder` is insecure and should not be used in production – replace with `BCryptPasswordEncoder` for secure password hashing.
- The alternative filter (`SimpleMagicHeaderFilter`) bypasses a separate `AuthenticationProvider` for simplicity, but this reduces modularity and reusability.

## Security Context Management in Multi-Threaded Environments

After successful authentication, the `AuthenticationManager` stores the `Authentication` object in the `SecurityContext`.

### How SecurityContext is Managed
- **Via `SecurityContextHolder`**: A static holder that manages storage strategies for the security context.
- **Strategies**:
  - **`MODE_THREADLOCAL`** (Default): Stores the context per thread. Suitable for standard web requests but does not propagate to async or child threads, leading to context loss.
  - **`MODE_INHERITABLETHREADLOCAL`**: Propagates the context to child threads created by the framework (e.g., in Tomcat). Recommended for applications with framework-managed threads.
  - **`MODE_GLOBAL`**: Shares the context across all threads. Rarely used due to security risks in multi-user applications.
- **Set Strategy**: Configure the strategy in a bean initializer, for example:
  ```java
  @Bean
  public InitializingBean initializeSecurityContext() {
      return () -> SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
  }
  ```

### Challenges in Async/Reactive Apps
- **Custom Threads**: Threads created manually (e.g., via `ExecutorService`) do not inherit the security context, causing authentication data to be unavailable.
- **Solutions**:
  - **`DelegatingSecurityContextRunnable`/`Callable`**: Wrap tasks to propagate the security context to custom threads. Example:
    ```java
    Runnable task = new DelegatingSecurityContextRunnable(originalRunnable);
    ```
  - **`DelegatingSecurityContextExecutorService`**: Decorate an `ExecutorService` to ensure context propagation. Example:
    ```java
    ExecutorService executor = Executors.newCachedThreadPool();
    executor = new DelegatingSecurityContextExecutorService(executor);
    ```

### Session Management
- For session persistence, use `HttpSessionSecurityContextRepository` to store the `SecurityContext` across requests.
- On logout, clear the context using `SecurityContextHolder.clearContext()` to ensure no residual authentication data remains.
