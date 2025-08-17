# Spring Security Filters

## Introduction to Spring Security Filters

Spring Security's filter chain is the backbone of its security architecture. Every request passes through a series of filters before reaching your controller.

### Why Filters?
- **Early interception**: Process requests before they reach the application
- **Cross-cutting concerns**: Handle security, logging, CORS, etc.
- **Chaining**: Multiple filters can process the same request
- **Flexibility**: Add custom logic at different points in the request lifecycle

### Filter Chain Flow
```
Client Request → Security Filter Chain → DispatcherServlet → Controller
```

---

## Filter Chain Architecture

### Security Filter Chain Structure
```java
// Default Spring Security Filter Chain (order matters!)
1. SecurityContextPersistenceFilter / SecurityContextHolderFilter
2. HeaderWriterFilter
3. CsrfFilter
4. LogoutFilter
5. UsernamePasswordAuthenticationFilter / BasicAuthenticationFilter
6. RequestCacheAwareFilter
7. SecurityContextHolderAwareRequestFilter
8. RememberMeAuthenticationFilter
9. AnonymousAuthenticationFilter
10. SessionManagementFilter
11. ExceptionTranslationFilter
12. FilterSecurityInterceptor / AuthorizationFilter
```

### Understanding Filter Order
Spring Security assigns specific orders to its filters. Custom filters are inserted based on their position relative to these built-in filters.

```java
public enum FilterOrderRegistration {
    FIRST(Integer.MIN_VALUE),
    SECURITY_CONTEXT_FILTER(0),
    HEADER_WRITER_FILTER(100),
    CSRF_FILTER(200),
    LOGOUT_FILTER(300),
    PRE_AUTH_FILTER(400),
    FORM_LOGIN_FILTER(500),
    BASIC_AUTH_FILTER(600),
    // ... and so on
}
```

---

## Built-in Security Filters

### 1. SecurityContextPersistenceFilter (Deprecated in 6.0)
**Replaced by SecurityContextHolderFilter**
- Loads/saves SecurityContext from/to storage (usually HTTP session)
- Ensures SecurityContext is available throughout the request

### 2. HeaderWriterFilter
- Adds security headers to HTTP response
- Headers like X-Frame-Options, X-Content-Type-Options, etc.

```java
// Configuration example
http.headers(headers -> headers
    .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
    .contentTypeOptions(Customizer.withDefaults())
    .httpStrictTransportSecurity(hsts -> hsts
        .maxAgeInSeconds(31536000)
        .includeSubdomains(true)
    )
);
```

### 3. CsrfFilter
- Protects against Cross-Site Request Forgery attacks
- Validates CSRF tokens on state-changing requests

### 4. LogoutFilter
- Handles logout requests
- Clears SecurityContext and invalidates session

### 5. UsernamePasswordAuthenticationFilter
- Processes username/password authentication from forms
- Only processes requests matching configured URL (default: `/login`)

```java
@Override
protected void doFilterInternal(HttpServletRequest request, 
                               HttpServletResponse response, 
                               FilterChain filterChain) throws ServletException, IOException {
    
    if (!requiresAuthentication(request, response)) {
        filterChain.doFilter(request, response);
        return;
    }
    
    // Extract username and password
    // Attempt authentication
    // Set authentication in SecurityContext
}
```

### 6. BasicAuthenticationFilter
- Processes HTTP Basic Authentication
- Extracts credentials from Authorization header

### 7. SecurityContextHolderAwareRequestFilter
- Populates ServletRequest with Spring Security-aware methods
- Provides methods like `isUserInRole()`, `getRemoteUser()`

### 8. AnonymousAuthenticationFilter
- Creates anonymous Authentication object if no authentication exists
- Ensures SecurityContext always has an Authentication object

### 9. SessionManagementFilter
- Handles session-related security concerns
- Session fixation protection, concurrent session control

### 10. ExceptionTranslationFilter
- Handles security exceptions (AccessDeniedException, AuthenticationException)
- Redirects to login page or returns appropriate HTTP status

### 11. AuthorizationFilter (FilterSecurityInterceptor in older versions)
- Performs authorization decisions
- Checks if authenticated user has required authorities

---

## Custom Filter Implementation

### Basic Filter Implementation
Your code shows a basic filter implementation. Here's an improved version:

```java
@Component
public class LoggingFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(LoggingFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
                        FilterChain filterChain) throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        // Log request details
        logger.info("Processing request: {} {}", 
                   httpRequest.getMethod(), 
                   httpRequest.getRequestURI());
        
        long startTime = System.currentTimeMillis();
        
        try {
            // Continue with the filter chain
            filterChain.doFilter(request, response);
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logger.info("Request processed in {} ms", duration);
        }
    }
}
```

### Getting Username in Filter
**Answer to your question:** Here's how to get the username in a filter:

```java
public class AuthenticationLoggingFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
                        FilterChain filterChain) throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        // Method 1: From SecurityContext (after authentication)
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() 
            && !(authentication instanceof AnonymousAuthenticationToken)) {
            
            String username = authentication.getName();
            logger.info("Authenticated user: {}", username);
        }
        
        // Method 2: From HTTP Basic Auth header (before authentication)
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            String base64Credentials = authHeader.substring("Basic ".length());
            String credentials = new String(Base64.getDecoder().decode(base64Credentials));
            String[] parts = credentials.split(":", 2);
            String username = parts[0];
            logger.info("Basic auth username: {}", username);
        }
        
        // Method 3: From request parameter (form login)
        String username = httpRequest.getParameter("username");
        if (username != null) {
            logger.info("Form username: {}", username);
        }
        
        filterChain.doFilter(request, response);
    }
}
```

### OncePerRequestFilter Implementation
**Why OncePerRequestFilter is popular:** It ensures the filter is executed only once per request, even in complex forwarding scenarios.

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String authHeader = request.getHeader("Authorization");
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        String jwt = authHeader.substring(7);
        String username = jwtService.extractUsername(jwt);
        
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = 
                    new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // Skip filter for certain endpoints
        return request.getRequestURI().startsWith("/public/");
    }
}
```

---

## Filter vs OncePerRequestFilter

### Why OncePerRequestFilter is Preferred

| Aspect | Filter | OncePerRequestFilter |
|--------|--------|---------------------|
| **Execution** | May execute multiple times per request | Executes exactly once per request |
| **Use Case** | Simple logging, basic processing | Authentication, authorization, complex logic |
| **Forwarding** | Executes on forwards/includes | Skips on forwards/includes |
| **Thread Safety** | Need to handle manually | Built-in protection |
| **Spring Integration** | Basic servlet filter | Spring-aware with additional hooks |

### OncePerRequestFilter Advantages
```java
public abstract class OncePerRequestFilter implements Filter {
    
    // Prevents multiple executions
    private static final String ALREADY_FILTERED_SUFFIX = ".FILTERED";
    
    @Override
    public final void doFilter(ServletRequest request, ServletResponse response, 
                              FilterChain filterChain) throws ServletException, IOException {
        
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            throw new ServletException("OncePerRequestFilter supports HTTP requests only");
        }
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();
        
        if (request.getAttribute(alreadyFilteredAttributeName) != null) {
            // Already filtered - skip
            filterChain.doFilter(request, response);
        } else {
            // First time - process
            request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);
            try {
                doFilterInternal(httpRequest, (HttpServletResponse) response, filterChain);
            } finally {
                request.removeAttribute(alreadyFilteredAttributeName);
            }
        }
    }
    
    protected abstract void doFilterInternal(HttpServletRequest request, 
                                           HttpServletResponse response, 
                                           FilterChain filterChain) throws ServletException, IOException;
}
```

---

## Filter Positioning and Order

### Adding Custom Filters
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            // Add filter BEFORE existing filter
            .addFilterBefore(new CustomAuthenticationFilter(), 
                           UsernamePasswordAuthenticationFilter.class)
            
            // Add filter AFTER existing filter
            .addFilterAfter(new LoggingFilter(), 
                          BasicAuthenticationFilter.class)
            
            // Add filter AT specific position (replaces existing)
            .addFilterAt(new CustomBasicAuthFilter(), 
                        BasicAuthenticationFilter.class)
            
            // Add filter with specific order
            .addFilter(new CustomFilter()) // Must implement Ordered interface
            
            .build();
    }
}
```

### Custom Filter with Order
```java
@Component
public class OrderedLoggingFilter extends OncePerRequestFilter implements Ordered {

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        // Filter logic here
        filterChain.doFilter(request, response);
    }

    @Override
    public int getOrder() {
        return FilterOrderRegistration.HEADER_WRITER_FILTER.getOrder() + 1;
    }
}
```

### Filter Configuration Example
```java
@Configuration
public class FilterConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(rateLimitFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(auditFilter(), ExceptionTranslationFilter.class)
            .addFilterBefore(corsFilter(), HeaderWriterFilter.class)
            .httpBasic(Customizer.withDefaults())
            .build();
    }

    @Bean
    public RateLimitFilter rateLimitFilter() {
        return new RateLimitFilter();
    }

    @Bean
    public AuditFilter auditFilter() {
        return new AuditFilter();
    }

    @Bean
    public CorsFilter corsFilter() {
        return new CorsFilter();
    }
}
```

---

## Common Use Cases

### 1. Rate Limiting Filter
```java
@Component
public class RateLimitFilter extends OncePerRequestFilter {
    
    private final Map<String, List<Long>> requestCounts = new ConcurrentHashMap<>();
    private final int MAX_REQUESTS = 10;
    private final long TIME_WINDOW = 60000; // 1 minute

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String clientIP = getClientIP(request);
        
        if (isRateLimited(clientIP)) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.getWriter().write("Rate limit exceeded");
            return;
        }
        
        filterChain.doFilter(request, response);
    }
    
    private boolean isRateLimited(String clientIP) {
        long now = System.currentTimeMillis();
        requestCounts.compute(clientIP, (key, timestamps) -> {
            if (timestamps == null) {
                timestamps = new ArrayList<>();
            }
            
            // Remove old timestamps
            timestamps.removeIf(timestamp -> now - timestamp > TIME_WINDOW);
            
            // Add current timestamp
            timestamps.add(now);
            
            return timestamps;
        });
        
        return requestCounts.get(clientIP).size() > MAX_REQUESTS;
    }
    
    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
```

### 2. Request/Response Logging Filter
```java
@Component
public class RequestResponseLoggingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RequestResponseLoggingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        // Wrap request and response to capture data
        ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(request);
        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(response);
        
        long startTime = System.currentTimeMillis();
        
        try {
            filterChain.doFilter(wrappedRequest, wrappedResponse);
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logRequestResponse(wrappedRequest, wrappedResponse, duration);
            
            // Important: Copy response content back to original response
            wrappedResponse.copyBodyToResponse();
        }
    }
    
    private void logRequestResponse(ContentCachingRequestWrapper request, 
                                  ContentCachingResponseWrapper response, 
                                  long duration) {
        
        String requestBody = new String(request.getContentAsByteArray(), StandardCharsets.UTF_8);
        String responseBody = new String(response.getContentAsByteArray(), StandardCharsets.UTF_8);
        
        logger.info("Request: {} {} - Body: {} - Duration: {}ms - Status: {}", 
                   request.getMethod(), 
                   request.getRequestURI(),
                   requestBody.isEmpty() ? "empty" : requestBody,
                   duration,
                   response.getStatus());
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // Skip logging for health check endpoints
        return request.getRequestURI().equals("/health") || 
               request.getRequestURI().startsWith("/actuator");
    }
}
```

### 3. Tenant Resolution Filter
```java
@Component
public class TenantResolutionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String tenantId = extractTenantId(request);
            TenantContext.setCurrentTenant(tenantId);
            filterChain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }
    
    private String extractTenantId(HttpServletRequest request) {
        // Method 1: From header
        String tenantHeader = request.getHeader("X-Tenant-ID");
        if (tenantHeader != null) {
            return tenantHeader;
        }
        
        // Method 2: From subdomain
        String serverName = request.getServerName();
        if (serverName.contains(".")) {
            return serverName.split("\\.")[0];
        }
        
        // Method 3: From path
        String path = request.getRequestURI();
        if (path.startsWith("/tenant/")) {
            return path.split("/")[2];
        }
        
        return "default";
    }
}

// Tenant Context
public class TenantContext {
    private static final ThreadLocal<String> currentTenant = new ThreadLocal<>();
    
    public static void setCurrentTenant(String tenantId) {
        currentTenant.set(tenantId);
    }
    
    public static String getCurrentTenant() {
        return currentTenant.get();
    }
    
    public static void clear() {
        currentTenant.remove();
    }
}
```

### 4. CORS Filter (Alternative to @CrossOrigin)
```java
@Component
public class CustomCorsFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        response.setHeader("Access-Control-Max-Age", "3600");
        
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }
        
        filterChain.doFilter(request, response);
    }
}
```

---

## Best Practices

### 1. Filter Design Principles
```java
// ✅ Good Filter Design
@Component
public class GoodFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(GoodFilter.class);
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        // 1. Always call filterChain.doFilter() unless terminating the request
        // 2. Use try-finally for cleanup
        // 3. Handle exceptions properly
        // 4. Log important events
        
        try {
            // Pre-processing logic
            preprocessRequest(request);
            
            // Continue filter chain
            filterChain.doFilter(request, response);
            
            // Post-processing logic
            postprocessResponse(response);
            
        } catch (Exception e) {
            logger.error("Error in filter processing", e);
            handleFilterException(request, response, e);
        } finally {
            // Cleanup resources
            cleanup();
        }
    }
    
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // Skip filter for specific patterns
        return request.getRequestURI().startsWith("/public/") ||
               request.getRequestURI().equals("/health");
    }
}
```

### 2. Error Handling in Filters
```java
@Component
public class ErrorHandlingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (AuthenticationException e) {
            handleAuthenticationException(response, e);
        } catch (AccessDeniedException e) {
            handleAccessDeniedException(response, e);
        } catch (Exception e) {
            handleGenericException(response, e);
        }
    }
    
    private void handleAuthenticationException(HttpServletResponse response, 
                                             AuthenticationException e) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        String jsonResponse = """
            {
                "error": "Authentication failed",
                "message": "%s",
                "timestamp": "%s"
            }
            """.formatted(e.getMessage(), Instant.now());
            
        response.getWriter().write(jsonResponse);
    }
}
```

### 3. Performance Considerations
```java
@Component
public class PerformantFilter extends OncePerRequestFilter {
    
    // Use caching for expensive operations
    private final ConcurrentHashMap<String, Boolean> authCache = new ConcurrentHashMap<>();
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        // 1. Early termination for static resources
        if (isStaticResource(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // 2. Cache expensive computations
        String cacheKey = generateCacheKey(request);
        Boolean cachedResult = authCache.get(cacheKey);
        
        if (cachedResult != null && cachedResult) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // 3. Perform expensive operation only when necessary
        boolean result = expensiveOperation(request);
        authCache.put(cacheKey, result);
        
        if (result) {
            filterChain.doFilter(request, response);
        } else {
            response.setStatus(HttpStatus.FORBIDDEN.value());
        }
    }
    
    private boolean isStaticResource(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.endsWith(".css") || uri.endsWith(".js") || 
               uri.endsWith(".png") || uri.endsWith(".jpg");
    }
}
```

### 4. Testing Filters
```java
@ExtendWith(MockitoExtension.class)
class LoggingFilterTest {
    
    @Mock
    private HttpServletRequest request;
    
    @Mock
    private HttpServletResponse response;
    
    @Mock
    private FilterChain filterChain;
    
    @InjectMocks
    private LoggingFilter loggingFilter;
    
    @Test
    void shouldLogRequestAndContinueChain() throws ServletException, IOException {
        // Given
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/test");
        
        // When
        loggingFilter.doFilter(request, response, filterChain);
        
        // Then
        verify(filterChain).doFilter(request, response);
        // Add assertions for logging if needed
    }
}

// Integration Test
@SpringBootTest
@AutoConfigureMockMvc
class FilterIntegrationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    void shouldApplyCustomFilter() throws Exception {
        mockMvc.perform(get("/api/test"))
            .andExpect(status().isOk())
            .andExpect(header().exists("X-Custom-Header"));
    }
}
```

---

## Interview Questions

### 🎯 Common Interview Questions

**1. What is the purpose of Spring Security filters?**

Spring Security filters form a chain that processes every HTTP request. They handle:
- Authentication (verifying identity)
- Authorization (checking permissions)
- Security headers
- CSRF protection
- Session management
- Exception handling

**2. Explain the difference between Filter and OncePerRequestFilter**

- **Filter**: Basic servlet filter, may execute multiple times per request in forwarding scenarios
- **OncePerRequestFilter**: Spring's filter that guarantees single execution per request, preferred for Spring applications

**3. How do you add a custom filter to Spring Security?**

```java
http.addFilterBefore(new CustomFilter(), ExistingFilter.class)
    .addFilterAfter(new AnotherFilter(), AnotherExistingFilter.class)
    .addFilterAt(new ReplacementFilter(), FilterToReplace.class)
```

**4. Where in the filter chain would you place different types of filters?**

- **Authentication filters**: Before `UsernamePasswordAuthenticationFilter`
- **Rate limiting**: Very early, before `SecurityContextPersistenceFilter`
- **Logging/Audit**: After `ExceptionTranslationFilter`
- **CORS**: Before `HeaderWriterFilter`

**5. How do you access the authenticated user in a custom filter?**

```java
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
if (auth != null && auth.isAuthenticated()) {
    String username = auth.getName();
    Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
}
```

**6. What happens if you don't call filterChain.doFilter()?**

The request processing stops at that filter. Subsequent filters and the actual endpoint won't be executed. This is useful for:
- Authentication failures
- Rate limiting
- Request rejection

**7. How do you handle exceptions in filters?**

```java
try {
    filterChain.doFilter(request, response);
} catch (AuthenticationException e) {
    // Handle authentication failure
    response.setStatus(401);
    response.getWriter().write("Authentication failed");
} catch (Exception e) {
    // Handle other exceptions
    logger.error("Filter error", e);
    response.setStatus(500);
}
```

### 🔑 Key Points for Interviews

- **Filter Order Matters**: Spring Security has a specific order for filters
- **OncePerRequestFilter**: Preferred for most custom filters
- **SecurityContext Access**: Available after authentication filters
- **Exception Handling**: Important to handle exceptions properly in filters
- **Performance**: Consider caching and early termination
