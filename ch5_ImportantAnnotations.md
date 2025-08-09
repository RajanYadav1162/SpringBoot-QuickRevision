# Spring Boot Annotations - Complete Reference Guide
---

## Core Spring Annotations

### @Component, @Service, @Repository, @Controller
**Purpose**: Mark classes as Spring-managed beans (stereotypes)

```java
@Component
public class MyComponent { }

@Service
public class UserService { }

@Repository
public class UserRepository { }

@Controller
public class WebController { }
```

**Interview Tip**: `@Service`, `@Repository`, `@Controller` are specializations of `@Component` with semantic meaning.

### @Autowired
**Purpose**: Dependency injection

```java
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    
    // Constructor injection (preferred)
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
}
```

### @Qualifier
**Purpose**: Resolve ambiguity when multiple beans of same type exist

```java
@Service
public class EmailService {
    @Autowired
    @Qualifier("gmailSender")
    private EmailSender emailSender;
}
```

### @Primary
**Purpose**: Mark a bean as primary when multiple candidates exist

```java
@Service
@Primary
public class PrimaryEmailService implements EmailService { }
```

### @Scope
**Purpose**: Define bean lifecycle and creation strategy

#### Singleton Scope (Default)
```java
@Service
@Scope("singleton") // or @Scope(ConfigurableBeanFactory.SCOPE_SINGLETON)
public class UserService {
    private int counter = 0; // Shared across all injections
}
```
**Behavior**: One instance per Spring container (shared globally)
**Use Case**: Stateless services, repositories, configurations

#### Prototype Scope
```java
@Service
@Scope("prototype") // or @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class TaskProcessor {
    private String taskId = UUID.randomUUID().toString(); // Unique per instance
}
```
**Behavior**: New instance every time bean is requested
**Use Case**: Stateful objects, thread-unsafe classes, command objects

#### Web Scopes (Spring MVC/WebFlux)

##### Request Scope
```java
@Component
@Scope("request") // or @Scope(WebApplicationContext.SCOPE_REQUEST)
public class RequestLogger {
    private String requestId = UUID.randomUUID().toString();
    private long startTime = System.currentTimeMillis();
}
```
**Behavior**: One instance per HTTP request
**Use Case**: Request-specific data, audit logging, user context

##### Session Scope
```java
@Component
@Scope("session") // or @Scope(WebApplicationContext.SCOPE_SESSION)
public class ShoppingCart {
    private List<Item> items = new ArrayList<>();
    private String userId;
}
```
**Behavior**: One instance per HTTP session
**Use Case**: Shopping carts, user preferences, session data

##### Application Scope
```java
@Component
@Scope("application") // or @Scope(WebApplicationContext.SCOPE_APPLICATION)
public class AppMetrics {
    private long totalRequests = 0;
    private Map<String, Integer> endpointCounts = new HashMap<>();
}
```
**Behavior**: One instance per ServletContext (web application)
**Use Case**: Application-wide counters, global metrics, shared caches

#### Custom Scope with Proxy
```java
@Service
@Scope(value = "prototype", proxyMode = ScopedProxyMode.TARGET_CLASS)
public class StatefulService {
    private String state;
    
    public void setState(String state) { this.state = state; }
    public String getState() { return state; }
}
```
**ProxyMode**: Creates proxy to handle scope lifecycle
- `NO` - No proxy (default)
- `INTERFACES` - JDK dynamic proxy
- `TARGET_CLASS` - CGLIB proxy

### Real-World Scope Examples

#### E-commerce Shopping Cart
```java
@Component
@Scope("session")
public class ShoppingCart {
    private List<CartItem> items = new ArrayList<>();
    private BigDecimal total = BigDecimal.ZERO;
    
    public void addItem(CartItem item) {
        items.add(item);
        calculateTotal();
    }
}

@RestController
public class CartController {
    @Autowired
    private ShoppingCart cart; // Same cart instance per user session
    
    @PostMapping("/cart/add")
    public ResponseEntity<String> addToCart(@RequestBody CartItem item) {
        cart.addItem(item);
        return ResponseEntity.ok("Item added");
    }
}
```

#### Request-Scoped Audit Logger
```java
@Component
@Scope("request")
public class AuditLogger {
    private String requestId = UUID.randomUUID().toString();
    private String userAgent;
    private long startTime = System.currentTimeMillis();
    
    @PostConstruct
    public void init() {
        // Extract request details
        HttpServletRequest request = ((ServletRequestAttributes) 
            RequestContextHolder.currentRequestAttributes()).getRequest();
        this.userAgent = request.getHeader("User-Agent");
    }
}

@RestController
public class UserController {
    @Autowired
    private AuditLogger auditLogger; // New instance per HTTP request
    
    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        auditLogger.log("Fetching user: " + id);
        return userService.findById(id);
    }
}
```

#### Prototype for Command Pattern
```java
@Component
@Scope("prototype")
public class EmailCommand {
    private String to;
    private String subject;
    private String body;
    private boolean sent = false;
    
    public void execute() {
        // Send email logic
        this.sent = true;
    }
}

@Service
public class EmailService {
    @Autowired
    private ApplicationContext context;
    
    public void sendEmail(String to, String subject, String body) {
        EmailCommand command = context.getBean(EmailCommand.class); // New instance
        command.setTo(to);
        command.setSubject(subject);
        command.setBody(body);
        command.execute();
    }
}
```

---

## Spring Boot Specific

### @SpringBootApplication
**Purpose**: Combines `@Configuration`, `@EnableAutoConfiguration`, `@ComponentScan`

```java
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

### @EnableAutoConfiguration
**Purpose**: Enable Spring Boot's auto-configuration

```java
@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class})
public class Application { }
```

### @ComponentScan
**Purpose**: Specify packages to scan for components

```java
@ComponentScan(basePackages = "com.example.service")
public class Application { }
```

### @ConditionalOnProperty
**Purpose**: Conditionally create beans based on properties

```java
@Service
@ConditionalOnProperty(name = "feature.enabled", havingValue = "true")
public class FeatureService { }
```

### @ConditionalOnClass / @ConditionalOnMissingClass
**Purpose**: Conditional bean creation based on classpath

```java
@Configuration
@ConditionalOnClass(Redis.class)
public class RedisConfig { }
```

---

## Web Layer Annotations

### @RestController
**Purpose**: Combines `@Controller` + `@ResponseBody`

```java
@RestController
@RequestMapping("/api/users")
public class UserController { }
```

### @RequestMapping & HTTP Method Variants
**Purpose**: Map HTTP requests to handler methods

```java
@RestController
public class UserController {
    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) { }
    
    @PostMapping("/users")
    public User createUser(@RequestBody User user) { }
    
    @PutMapping("/users/{id}")
    public User updateUser(@PathVariable Long id, @RequestBody User user) { }
    
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) { }
    
    @PatchMapping("/users/{id}")
    public User patchUser(@PathVariable Long id, @RequestBody Map<String, Object> updates) { }
}
```

### @PathVariable, @RequestParam, @RequestBody
**Purpose**: Extract data from HTTP requests

```java
@GetMapping("/users/{id}")
public User getUser(@PathVariable Long id, 
                   @RequestParam(defaultValue = "0") int page,
                   @RequestHeader("Authorization") String token) { }

@PostMapping("/users")
public User createUser(@RequestBody User user) { }
```

### @ResponseStatus
**Purpose**: Set HTTP status code for responses

```java
@PostMapping("/users")
@ResponseStatus(HttpStatus.CREATED)
public User createUser(@RequestBody User user) { }
```

### @ExceptionHandler
**Purpose**: Handle exceptions in controllers

```java
@RestController
public class UserController {
    @ExceptionHandler(UserNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorResponse handleUserNotFound(UserNotFoundException ex) {
        return new ErrorResponse("User not found");
    }
}
```

### @ControllerAdvice / @RestControllerAdvice
**Purpose**: Global exception handling

```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGeneral(Exception ex) {
        return ResponseEntity.status(500).body("Internal error");
    }
}
```

---

## Data & Repository

### @Entity, @Table, @Id
**Purpose**: JPA entity mapping

```java
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "email", unique = true)
    private String email;
}
```

### @Repository
**Purpose**: Mark data access layer + exception translation

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    List<User> findByEmail(String email);
}
```

### @Query
**Purpose**: Custom JPQL/SQL queries

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.email = ?1")
    Optional<User> findByEmail(String email);
    
    @Query(value = "SELECT * FROM users WHERE active = 1", nativeQuery = true)
    List<User> findActiveUsers();
}
```

### @Transactional
**Purpose**: Transaction management

```java
@Service
@Transactional
public class UserService {
    @Transactional(readOnly = true)
    public User findById(Long id) { }
    
    @Transactional(rollbackFor = Exception.class)
    public User save(User user) { }
}
```

---

## Configuration & Properties

### @Configuration
**Purpose**: Mark class as configuration source

```java
@Configuration
public class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
```

### @Bean
**Purpose**: Create Spring-managed beans

```java
@Configuration
public class DatabaseConfig {
    @Bean
    @Primary
    public DataSource primaryDataSource() {
        return DataSourceBuilder.create().build();
    }
}
```

### @Value
**Purpose**: Inject property values

```java
@Service
public class EmailService {
    @Value("${app.email.from}")
    private String fromEmail;
    
    @Value("${app.email.timeout:5000}")
    private int timeout; // Default 5000 if property missing
}
```

### @ConfigurationProperties
**Purpose**: Bind properties to Java objects

```java
@ConfigurationProperties(prefix = "app.database")
@Component
public class DatabaseProperties {
    private String url;
    private String username;
    private int maxConnections;
    
    // getters and setters
}
```

### @EnableConfigurationProperties
**Purpose**: Enable configuration properties classes

```java
@Configuration
@EnableConfigurationProperties(DatabaseProperties.class)
public class AppConfig { }
```

### @Profile
**Purpose**: Activate beans for specific environments

```java
@Service
@Profile("dev")
public class DevEmailService implements EmailService { }

@Service
@Profile("prod")
public class ProdEmailService implements EmailService { }
```

---

## Testing Annotations

### @SpringBootTest
**Purpose**: Load complete Spring context for integration tests

```java
@SpringBootTest
class UserServiceTest {
    @Autowired
    private UserService userService;
}
```

### @WebMvcTest
**Purpose**: Test web layer only

```java
@WebMvcTest(UserController.class)
class UserControllerTest {
    @Autowired
    private MockMvc mockMvc;
    
    @MockBean
    private UserService userService;
}
```

### @DataJpaTest
**Purpose**: Test JPA repositories with in-memory database

```java
@DataJpaTest
class UserRepositoryTest {
    @Autowired
    private TestEntityManager entityManager;
    
    @Autowired
    private UserRepository userRepository;
}
```

### @MockBean, @SpyBean
**Purpose**: Mock or spy on beans in tests

```java
@SpringBootTest
class UserServiceTest {
    @MockBean
    private UserRepository userRepository;
    
    @SpyBean
    private EmailService emailService;
}
```

### @Test, @BeforeEach, @AfterEach
**Purpose**: JUnit 5 test lifecycle

```java
class UserServiceTest {
    @BeforeEach
    void setUp() { }
    
    @Test
    void shouldCreateUser() { }
    
    @AfterEach
    void tearDown() { }
}
```

---

## Security Annotations

### @EnableWebSecurity
**Purpose**: Enable Spring Security

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) { }
}
```

### @PreAuthorize, @PostAuthorize
**Purpose**: Method-level security

```java
@Service
public class UserService {
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(Long id) { }
    
    @PreAuthorize("@userService.isOwner(#id, authentication.name)")
    public User getUser(Long id) { }
}
```

### @Secured, @RolesAllowed
**Purpose**: Role-based method security

```java
@Service
public class AdminService {
    @Secured("ROLE_ADMIN")
    public void adminOperation() { }
    
    @RolesAllowed({"ADMIN", "MANAGER"})
    public void managementOperation() { }
}
```

---

## Validation Annotations

### @Valid, @Validated
**Purpose**: Enable validation

```java
@RestController
public class UserController {
    @PostMapping("/users")
    public User createUser(@Valid @RequestBody User user) { }
}

@Service
@Validated
public class UserService {
    public User save(@Valid User user) { }
}
```

### JSR-303 Validation Annotations
**Purpose**: Field-level validation

```java
@Entity
public class User {
    @NotNull
    @Email
    private String email;
    
    @NotBlank
    @Size(min = 2, max = 50)
    private String name;
    
    @Min(18)
    @Max(120)
    private Integer age;
    
    @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$")
    private String phone;
}
```

---

## Additional Important Annotations

### @Async
**Purpose**: Asynchronous method execution

```java
@Service
public class EmailService {
    @Async
    public CompletableFuture<Void> sendEmail(String to, String message) {
        // Send email asynchronously
        return CompletableFuture.completedFuture(null);
    }
}

@Configuration
@EnableAsync
public class AsyncConfig { }
```

### @Scheduled
**Purpose**: Schedule method execution

```java
@Component
public class ScheduledTasks {
    @Scheduled(fixedRate = 5000)
    public void reportCurrentTime() { }
    
    @Scheduled(cron = "0 0 * * * *")
    public void hourlyTask() { }
}

@Configuration
@EnableScheduling
public class SchedulingConfig { }
```

### @EventListener
**Purpose**: Handle application events

```java
@Component
public class UserEventListener {
    @EventListener
    public void handleUserCreated(UserCreatedEvent event) { }
    
    @Async
    @EventListener
    public void handleAsync(UserDeletedEvent event) { }
}
```

### @Cacheable, @CacheEvict
**Purpose**: Caching support

```java
@Service
public class UserService {
    @Cacheable(value = "users", key = "#id")
    public User findById(Long id) { }
    
    @CacheEvict(value = "users", key = "#user.id")
    public User update(User user) { }
    
    @CacheEvict(value = "users", allEntries = true)
    public void clearCache() { }
}
```

### @Retryable
**Purpose**: Retry failed method calls

```java
@Service
public class ExternalApiService {
    @Retryable(value = {Exception.class}, maxAttempts = 3, backoff = @Backoff(delay = 1000))
    public String callExternalApi() { }
    
    @Recover
    public String recover(Exception ex) {
        return "Fallback response";
    }
}
```

---

## Interview Quick Reference

### Must-Know Annotations by Category

#### **Dependency Injection**
- `@Autowired` - Inject dependencies
- `@Qualifier` - Resolve bean conflicts  
- `@Primary` - Mark preferred bean

#### **Web Development**
- `@RestController` - REST endpoints
- `@GetMapping`, `@PostMapping` - HTTP mappings
- `@PathVariable`, `@RequestParam`, `@RequestBody` - Extract request data
- `@ExceptionHandler`, `@ControllerAdvice` - Error handling

#### **Data Access**
- `@Entity`, `@Id` - JPA entities
- `@Repository` - Data access layer
- `@Transactional` - Transaction management
- `@Query` - Custom queries

#### **Configuration**
- `@Configuration` - Configuration classes
- `@Bean` - Bean definitions
- `@Value`, `@ConfigurationProperties` - Property injection
- `@Profile` - Environment-specific beans

#### **Testing**
- `@SpringBootTest` - Integration tests
- `@WebMvcTest` - Web layer tests
- `@DataJpaTest` - Repository tests
- `@MockBean` - Mock dependencies

### Common Interview Questions

**Q: Difference between @Component and @Service?**
A: Both create beans, but @Service adds semantic meaning for business logic layer and enables future AOP enhancements.

**Q: @Autowired vs Constructor Injection?**
A: Constructor injection is preferred (immutable, testable, explicit dependencies). @Autowired on fields/setters creates mutable dependencies.

**Q: When to use @Primary vs @Qualifier?**
A: @Primary sets default bean for type. @Qualifier explicitly selects specific bean by name.

**Q: @RestController vs @Controller?**
A: @RestController = @Controller + @ResponseBody. Use @RestController for REST APIs, @Controller for traditional MVC.

**Q: @SpringBootTest vs @WebMvcTest?**
A: @SpringBootTest loads full context (slower, integration tests). @WebMvcTest loads only web layer (faster, unit tests).

### Annotation Combinations to Remember

```java
// REST API Controller
@RestController
@RequestMapping("/api/v1/users")
@Validated
public class UserController { }

// Service Layer
@Service
@Transactional
@Validated
public class UserService { }

// Configuration Class
@Configuration
@EnableConfigurationProperties(AppProperties.class)
@Profile("prod")
public class ProductionConfig { }

// JPA Entity
@Entity
@Table(name = "users")
@EntityListeners(AuditingEntityListener.class)
public class User { }

// Test Class
@SpringBootTest
@TestPropertySource(locations = "classpath:test.properties")
@ActiveProfiles("test")
class UserServiceTest { }
```

### Pro Tips for Interviews

1. **Know the Hierarchy**: `@Component` → `@Service`/`@Repository`/`@Controller` → `@RestController`
2. **Understand Scopes**: 
   - `@Scope("singleton")` - One instance per container (default, thread-safe concerns)
   - `@Scope("prototype")` - New instance per request (stateful objects)
   - `@Scope("request")` - Per HTTP request (web apps only)
   - `@Scope("session")` - Per HTTP session (user-specific data)
3. **Lifecycle Annotations**: `@PostConstruct`, `@PreDestroy`
4. **Remember Validation**: `@Valid` vs `@Validated` (class-level vs method-level)
5. **Testing Strategy**: Know which test annotation to use for which layer

### Scope Interview Questions & Answers

**Q: What's the default scope in Spring?**
A: Singleton. One instance is created and shared across the entire application context.

**Q: When would you use prototype scope?**
A: For stateful beans, thread-unsafe objects, or when you need a fresh instance each time (e.g., command objects, form backing beans).

**Q: What's the difference between singleton and application scope?**
A: Singleton is per Spring container, application scope is per ServletContext. In most cases, they're equivalent, but application scope is web-specific.

**Q: Why use request scope for logging?**
A: Each HTTP request gets its own logger instance with unique request ID, making it easy to trace logs for a specific request without thread-safety issues.

**Q: What happens if you inject prototype bean into singleton?**
A: You get the same prototype instance every time. Use `@Lookup` method injection or `ApplicationContext.getBean()` to get fresh instances.

**Q: When do you need proxyMode in @Scope?**
A: When injecting shorter-lived scopes (request, session) into longer-lived scopes (singleton). The proxy ensures the correct instance is used at runtime.
