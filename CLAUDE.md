# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**IES Security Core** is a Clean Architecture implementation of the security module for the IES (Content Management System) application. This is a framework-agnostic, infrastructure-independent core library that contains domain entities, business logic (use cases), and port interfaces for security operations.

The module handles:
- User authentication (password, LDAP, OIDC, WebAuthn)
- Multi-factor authentication (TOTP, WebAuthn)
- Access token management (private, service, impersonation tokens)
- Session management
- Password recovery
- Authorization and access control

## Build Commands

### Standard Build Operations
```bash
# Clean and compile
mvn clean compile

# Run all tests
mvn test

# Run a single test class
mvn test -Dtest=SessionTest

# Run a specific test method
mvn test -Dtest=SessionTest#testId

# Full build with all quality checks
mvn clean verify

# Generate JaCoCo coverage report
mvn jacoco:report
# Report will be in target/site/jacoco/index.html
```

### Code Quality Commands
```bash
# Format code (Google Java Style)
mvn spotless:apply

# Check code formatting
mvn spotless:check

# Run SpotBugs analysis
mvn spotbugs:check

# Run PMD analysis
mvn pmd:check

# Run all quality checks (verify phase includes these)
mvn verify
```

### Dependency Management
```bash
# View dependency tree
mvn dependency:tree

# Check for dependency updates
mvn versions:display-dependency-updates

# Analyze dependencies
mvn dependency:analyze
```

## Architecture

This project follows **Clean Architecture** principles with clear separation between domain logic and infrastructure concerns.

### Package Structure

```
com.sitepark.ies.security.core/
├── domain/                    # Domain layer (framework-independent)
│   ├── entity/               # Domain entities (Session, AccessToken, WebAuthnRegisteredCredential)
│   ├── value/                # Value objects (AuthenticationResult, TokenType, etc.)
│   ├── service/              # Domain services (AccessControl)
│   └── exception/            # Domain exceptions
├── port/                      # Port interfaces (adapters implement these)
│   ├── AccessTokenRepository.java
│   ├── AuthenticationProvider.java
│   ├── SessionRegistry.java
│   ├── UserService.java
│   ├── TokenService.java
│   ├── Vault.java
│   └── ...                   # Other repository/service interfaces
├── usecase/                   # Application layer (use cases)
│   ├── password/             # Password authentication use cases
│   ├── token/                # Token management use cases
│   ├── session/              # Session management use cases
│   ├── totp/                 # TOTP (MFA) use cases
│   ├── webauthn/             # WebAuthn use cases
│   ├── oidc/                 # OIDC authentication use cases
│   └── code/                 # Code verification use cases
└── service/                   # Application services (currently empty)
```

### Clean Architecture Layers

1. **Domain Layer** (`domain/`)
   - Contains core business entities and rules
   - Zero dependencies on frameworks or infrastructure
   - Entities use Builder pattern for immutability
   - Domain services encapsulate complex business logic (e.g., `AccessControl`)

2. **Use Case Layer** (`usecase/`)
   - Contains application-specific business rules
   - Orchestrates flow of data to/from entities
   - Uses port interfaces to interact with external concerns
   - Each use case is a distinct class (e.g., `PasswordAuthenticationUseCase`, `CreatePrivateTokenUserCase`)

3. **Port Layer** (`port/`)
   - Defines interfaces that infrastructure adapters must implement
   - Enables dependency inversion (domain doesn't depend on infrastructure)
   - Examples: `UserService`, `SessionRegistry`, `TokenService`, `Vault`, `WebAuthnProvider`

### Key Architecture Patterns

#### Dependency Injection
- Uses Jakarta Inject (`@Inject`) for constructor injection
- All dependencies are injected through constructors
- No field injection

#### Port/Adapter Pattern
- Ports are interfaces in `port/` package
- Implementations are provided by infrastructure layer (not in this module)
- Examples:
  - `UserService`: Load user data from storage
  - `SessionRegistry`: Manage session persistence
  - `Vault`: Secure credential storage
  - `TokenService`: Token cryptography operations

#### Use Case Pattern
- Each business operation is a separate use case class
- Use cases coordinate between domain entities and ports
- Example flow: `PasswordAuthenticationUseCase`
  1. Check rate limiting via `AuthenticationAttemptLimiter`
  2. Load user via `UserService`
  3. Authenticate against LDAP or internal password
  4. Check for additional authentication factors
  5. Store partial state if MFA required
  6. Return `AuthenticationResult`

#### Domain Service Pattern
- `AccessControl` is a domain service that centralizes authorization logic
- Checks permissions based on current authentication context
- Used across multiple use cases

### Authentication Flow

The module supports multi-step authentication:

1. **Initial Authentication** (password/LDAP/OIDC/WebAuthn)
   - Returns `AuthenticationResult` which can be:
     - `success()`: Full authentication complete
     - `partial()`: Additional factors required (TOTP, etc.)
     - `failure()`: Authentication failed

2. **Multi-Factor Authentication** (if required)
   - Partial authentication returns process ID and requirements
   - Subsequent use cases verify additional factors (TOTP codes, etc.)
   - State is stored via `TotpAuthenticationProcessStore`

3. **Session Creation**
   - Successful authentication creates session via `SessionRegistry`
   - Sessions track authentication method, purpose, and user

### Token Management

Three types of access tokens:
- **Private Tokens**: User-owned tokens for API access
- **Service Tokens**: System service authentication
- **Impersonation Tokens**: Admin ability to act as another user

Token lifecycle managed through:
- `AccessTokenRepository`: Persistence
- `TokenService`: Cryptographic operations
- Various use cases for creation/revocation/retrieval

## Development Guidelines

### Entity Design
- All entities use immutable Builder pattern
- Implement `equals()`, `hashCode()`, and `toString()`
- Use `@NotNull` annotations for required fields
- Validation in builder methods, not constructors

### Use Case Design
- Constructor injection for all dependencies
- Clear single responsibility per use case
- Return domain value objects, not primitives
- Throw domain exceptions from `domain/exception/`

### Port Interface Design
- Keep interfaces focused and minimal
- Return `Optional<T>` for potentially missing data
- Use domain types in method signatures
- Document expected behavior in Javadoc

## Testing Approach

### Test Libraries
- JUnit 5 for test framework
- Mockito for mocking ports and dependencies
- AssertJ for fluent assertions (already configured via BOM)
- EqualsVerifier for testing `equals()` and `hashCode()`
- ToStringVerifier for testing `toString()`

### Test Structure Example
```java
@Test
void testMethodName() {
  // Arrange
  Session session = Session.builder()
    .id("1")
    .purpose("test")
    .build();

  // Act
  String result = session.id();

  // Assert
  assertEquals("1", result, "Session id should match the provided value");
}
```

### Testing Patterns
- Test entities using EqualsVerifier and ToStringVerifier
- Mock port interfaces in use case tests
- Test validation by asserting on thrown exceptions
- Use descriptive assertion messages that explain expected behavior

## Key Dependencies

- **Java 21**: LTS version with modern language features
- **Jackson**: JSON serialization (for value objects)
- **Log4j2**: Logging framework
- **Jakarta Inject**: Dependency injection API
- **ies-shared-kernel**: Shared domain types (`User`, `Authentication`, etc.)

## Code Quality Standards

The build enforces:
- **Spotless**: Google Java Style formatting
- **SpotBugs**: Static bug detection (max effort, low threshold)
- **PMD**: Code quality rules (custom ruleset in `pmd-ruleset.xml`)
- **JaCoCo**: Code coverage reporting (configured but threshold at 0%)
- **Maven Enforcer**: Requires Maven 3.8+ and Java 21

All quality checks run during `mvn verify` phase.

## Important Notes

### Shared Kernel Dependency
This module depends on `ies-shared-kernel` for core security types:
- `User`: User entity with identity (internal/LDAP/OIDC)
- `Authentication`: Base authentication interface
- `UserAuthentication`: User-based authentication
- `PasswordEncoder`: Password hashing interface
- `AuthFactor`, `AuthMethod`: Authentication enumerations

When working with security concepts, check shared-kernel first.

### Purpose Field
Many operations require a "purpose" parameter (e.g., "login", "api", "admin"):
- Sessions track their purpose
- Authentication results include purpose
- Purpose enables different security policies per use case

### Clock Injection
Use cases inject `Clock` for time operations:
- Enables deterministic testing
- Use `Instant.now(clock)` instead of `Instant.now()`
- Supports different timezones in tests
