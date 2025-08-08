# 🚀 Spring Boot - Async Request Handling & HTTPS Complete Guide

## 1. Async Request Handling

### 1.1 Why Use Async?
- **Goal**: Free servlet threads immediately → container can handle more concurrent requests
- **Benefit**: Better scalability under high load
- **Key Point**: Servlet thread is released, actual work happens in background thread pool

### 1.2 Controller Layer - Return Types (No Annotation Needed)

| Return Type | Best For | Code Example | Interview Priority |
|-------------|----------|--------------|-------------------|
| `Callable<T>` | Simple async tasks | `return () -> service.process();` | ⭐⭐⭐ High |
| `CompletableFuture<T>` | Complex async pipelines | `return CompletableFuture.supplyAsync(() -> service.process());` | ⭐⭐⭐ High |
| `DeferredResult<T>` | Set result from another thread | `DeferredResult<String> dr = new DeferredResult<>();` | ⭐⭐ Medium |
| `SseEmitter` | Server-Sent Events | `SseEmitter emitter = new SseEmitter();` | ⭐ Low |
| `ResponseBodyEmitter` | Streaming JSON responses | `ResponseBodyEmitter emitter = new ResponseBodyEmitter();` | ⭐ Low |
| `StreamingResponseBody` | Binary file streaming | `return out -> Files.copy(path, out);` | ⭐ Low |

#### Example: Callable vs CompletableFuture

```java
@RestController
public class AsyncController {
    
    @Autowired
    private AsyncTaskExecutor asyncTaskExecutor;
    
    // 1. Using Callable (Spring handles thread management)
    @GetMapping("/callable")
    public Callable<String> handleCallable() {
        System.out.println("Controller thread: " + Thread.currentThread().getName());
        return () -> {
            System.out.println("Worker thread: " + Thread.currentThread().getName());
            Thread.sleep(2000); // simulate work
            return "Processed by Callable";
        };
    }
    
    // 2. Using CompletableFuture (Manual executor control)
    @GetMapping("/future")
    public CompletableFuture<String> handleFuture() {
        return asyncTaskExecutor.submitCompletable(() -> {
            System.out.println("Worker thread: " + Thread.currentThread().getName());
            Thread.sleep(2000);
            return "Processed by CompletableFuture";
        });
    }
}
```

### 1.3 Service Layer - @Async Annotation Required

```java
@Service
public class AsyncService {
    
    // Fire-and-forget (no return value needed)
    @Async
    public void sendEmail(String to, String subject) {
        // runs in background thread
        emailService.send(to, subject);
    }
    
    // Fire-and-get-result-later
    @Async("customExecutor")
    public CompletableFuture<String> processLargeFile(String filename) {
        String result = heavyFileProcessing(filename);
        return CompletableFuture.completedFuture(result);
    }
}
```

### 1.4 Configuration - Custom Thread Pool

```java
@Configuration
@EnableAsync  // Required for @Async to work
public class AsyncConfig implements WebMvcConfigurer {
    
    // For @Async methods
    @Bean("customExecutor")
    public AsyncTaskExecutor customExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(8);
        executor.setMaxPoolSize(32);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("Custom-Async-");
        executor.initialize(); // CRITICAL: Must call this!
        return executor;
    }
    
    // For Controller async (Callable/CompletableFuture)
    @Override
    public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
        configurer.setDefaultTimeout(30000);
        configurer.setTaskExecutor(customExecutor());
    }
}
```

### 1.5 Key Differences Summary

| Layer | Async Support | Annotation Required | Thread Management |
|-------|---------------|-------------------|-------------------|
| **Controller** | ✅ Yes | ❌ No | Return `Callable`/`CompletableFuture` |
| **Service** | ✅ Yes | ✅ `@Async` | Spring creates proxy, manages threads |

---

## 2. AsyncTaskExecutor Implementations

### 2.1 Production-Ready Implementations

| Implementation | JDK | Use Case | Characteristics |
|----------------|-----|----------|-----------------|
| `ThreadPoolTaskExecutor` | 8+ | **95% of apps** - REST APIs, @Async services | Configurable pool, queue, rejection policy |
| `VirtualThreadTaskExecutor` | 21+ | High-concurrency apps (1M+ threads) | Lightweight virtual threads (Project Loom) |
| `SimpleAsyncTaskExecutor` | 8+ | **Testing only** | Creates new thread every time - no pooling |
| `ConcurrentTaskExecutor` | 8+ | Wrap existing JDK Executor | Adapter for `ExecutorService` |

### 2.2 Real-World Configuration Examples

#### ThreadPoolTaskExecutor (Most Common)
```java
@Bean("ioTaskExecutor")
public AsyncTaskExecutor ioTaskExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(Runtime.getRuntime().availableProcessors());
    executor.setMaxPoolSize(50);
    executor.setQueueCapacity(1000);
    executor.setThreadNamePrefix("IO-");
    executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
    executor.initialize();
    return executor;
}
```

#### VirtualThreadTaskExecutor (Java 21+)
```java
@Bean("virtualExecutor")
public AsyncTaskExecutor virtualExecutor() {
    return new VirtualThreadTaskExecutor("vt-");
}
```

#### Spring Boot Auto-Configuration
```yaml
# application.yml
spring:
  task:
    execution:
      pool:
        core-size: 8
        max-size: 32
        queue-capacity: 100
      thread-name-prefix: "boot-async-"
```

### 2.3 Choosing the Right Executor

| Workload Type | Recommendation |
|---------------|----------------|
| **CPU-intensive** | `ThreadPoolTaskExecutor` with core = CPU cores |
| **I/O-bound** (REST, DB calls) | `ThreadPoolTaskExecutor` with larger pool (50-200) |
| **Very high concurrency** | `VirtualThreadTaskExecutor` (Java 21+) |
| **Enterprise servers** | `WorkManagerTaskExecutor` |
| **Testing** | `SimpleAsyncTaskExecutor` |

---

## 3. HTTPS/SSL Configuration

### 3.1 Core Concepts

| Term | Description |
|------|-------------|
| **Certificate** | Digital passport proving server identity |
| **Keystore** | File containing private key + certificate (PKCS12/JKS) |
| **Truststore** | Certificates you trust (CA certificates) |
| **Self-signed** | For localhost/development |
| **CA-signed** | For production (Let's Encrypt, DigiCert) |

### 3.2 Local Development Setup

#### Step 1: Generate Self-Signed Certificate
```bash
keytool -genkeypair \
  -alias myapp \
  -keyalg RSA \
  -keysize 2048 \
  -storetype PKCS12 \
  -keystore keystore.p12 \
  -validity 3650
```

**Prompts:**
- Password: `changeit`
- First/Last name: `localhost`
- Organization: `MyCompany`

#### Step 2: Configure application.properties
```properties
server.port=8443
server.ssl.enabled=true
server.ssl.key-store=classpath:keystore.p12
server.ssl.key-store-type=PKCS12
server.ssl.key-store-password=changeit
server.ssl.key-alias=myapp

# Optional: Force HTTPS redirect
server.ssl.require-ssl=true
```

#### Step 3: Test
```bash
# Browser (expect security warning)
https://localhost:8443/api/hello

# cURL (skip SSL verification for self-signed)
curl -k https://localhost:8443/api/hello
```

### 3.3 Production Configuration

#### Option 1: App-Level SSL Termination
```properties
server.ssl.key-store=file:/etc/ssl/certs/app.p12
server.ssl.key-store-password=${SSL_KEYSTORE_PASSWORD}
server.ssl.key-store-type=PKCS12
server.ssl.protocol=TLS
server.ssl.enabled-protocols=TLSv1.2,TLSv1.3
```

#### Option 2: Load Balancer SSL Termination (Recommended)
```yaml
# nginx/ALB handles SSL, forwards HTTP to Spring Boot
server:
  port: 8080  # HTTP only
  forward-headers-strategy: native
```

### 3.4 Common SSL Properties

```properties
# Security settings
server.ssl.ciphers=TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256
server.ssl.protocol=TLS
server.ssl.enabled-protocols=TLSv1.2,TLSv1.3

# Client authentication (mutual TLS)
server.ssl.client-auth=need
server.ssl.trust-store=classpath:truststore.p12
server.ssl.trust-store-password=changeit
```

---

## 4. Interview Cheat Sheet

### 4.1 Key Talking Points

**Async Request Handling:**
> *"I use `Callable` or `CompletableFuture` return types in controllers to make requests asynchronous. This frees up servlet threads immediately, allowing the container to handle more concurrent requests. For service-layer async processing, I annotate methods with `@Async` and configure a custom `ThreadPoolTaskExecutor` for better control over thread pool parameters."*

**SSL/HTTPS Setup:**
> *"For local development, I generate self-signed certificates using `keytool` and configure Spring Boot via `server.ssl.*` properties. In production, I either use CA-signed certificates directly in the application or terminate SSL at the load balancer level for better performance and certificate management."*

### 4.2 Common Interview Questions & Answers

**Q: What's the difference between @Async and returning Callable from controller?**
- **Controller async**: No annotation needed, return `Callable`/`CompletableFuture` → Spring MVC handles thread management
- **Service async**: Requires `@Async` annotation → Spring creates proxy, runs method in background thread

**Q: How do you configure custom thread pools?**
- Create `@Bean` of type `AsyncTaskExecutor` or `ThreadPoolTaskExecutor`
- Configure core/max pool size, queue capacity, thread naming
- **Critical**: Call `executor.initialize()` when creating manually
- Use `@Async("beanName")` to specify which executor to use

**Q: Why use HTTPS?**
- **Encryption**: Protects data in transit
- **Authentication**: Verifies server identity
- **Integrity**: Prevents data tampering
- **Compliance**: Required for production APIs

**Q: Self-signed vs CA-signed certificates?**
- **Self-signed**: Quick setup for development, browsers show warnings
- **CA-signed**: Trusted by browsers, required for production
- **Let's Encrypt**: Free CA-signed certificates with auto-renewal

### 4.3 Code Snippets to Remember

```java
// 1. Async Controller (no annotation needed)
@GetMapping("/async")
public CompletableFuture<String> asyncEndpoint() {
    return CompletableFuture.supplyAsync(() -> {
        // background processing
        return "result";
    });
}

// 2. Async Service (annotation required)
@Async("customExecutor")
public CompletableFuture<String> processData() {
    // runs in background thread
    return CompletableFuture.completedFuture("processed");
}

// 3. Custom Executor Configuration
@Bean
public AsyncTaskExecutor customExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(8);
    executor.setMaxPoolSize(32);
    executor.initialize(); // DON'T FORGET!
    return executor;
}
```

### 4.4 Best Practices Checklist

- ✅ Use `ThreadPoolTaskExecutor` for production (not `SimpleAsyncTaskExecutor`)
- ✅ Always call `executor.initialize()` when creating beans manually
- ✅ Configure appropriate pool sizes based on workload type
- ✅ Use constructor injection over field injection
- ✅ Terminate SSL at load balancer in production for better performance
- ✅ Use Let's Encrypt for free CA-signed certificates
- ✅ Configure proper SSL protocols and ciphers for security

---

## 5. Bonus: Complete Working Example

```java
@SpringBootApplication
@EnableAsync
public class AsyncHttpsApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(AsyncHttpsApplication.class, args);
    }
    
    @Bean
    public AsyncTaskExecutor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(4);
        executor.setMaxPoolSize(16);
        executor.setQueueCapacity(50);
        executor.setThreadNamePrefix("Async-");
        executor.initialize();
        return executor;
    }
}

@RestController
public class DemoController {
    
    private final AsyncTaskExecutor taskExecutor;
    private final AsyncService asyncService;
    
    public DemoController(AsyncTaskExecutor taskExecutor, AsyncService asyncService) {
        this.taskExecutor = taskExecutor;
        this.asyncService = asyncService;
    }
    
    @GetMapping("/callable")
    public Callable<String> callableDemo() {
        return () -> {
            Thread.sleep(1000);
            return "Callable result from: " + Thread.currentThread().getName();
        };
    }
    
    @GetMapping("/future")
    public CompletableFuture<String> futureDemo() {
        return taskExecutor.submitCompletable(() -> {
            Thread.sleep(1000);
            return "Future result from: " + Thread.currentThread().getName();
        });
    }
    
    @GetMapping("/service-async")
    public CompletableFuture<String> serviceAsyncDemo() {
        return asyncService.processAsync("demo-data");
    }
}

@Service
public class AsyncService {
    
    @Async
    public CompletableFuture<String> processAsync(String data) {
        try {
            Thread.sleep(1000);
            return CompletableFuture.completedFuture(
                "Service processed: " + data + " on: " + Thread.currentThread().getName()
            );
        } catch (InterruptedException e) {
            return CompletableFuture.completedFuture("Error");
        }
    }
}
```

---
