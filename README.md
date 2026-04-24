# BCryptExtended 2.1

> 🔒 **Zaawansowana implementacja BCrypt** 

## 📋 O Projekcie

**BCryptExtended** to rozszerzenie natywnego algorytmu BCrypt z zaawansowanymi funkcjami:

| Funkcja | Opis |
|---------|------|
| 🔐 **Haszowanie** | Bezpieczne haszowanie haseł z konfigurowalnymi parametrami |
| ✅ **Walidacja** | Pełna walidacja siły haseł wg standardów OWASP |
| ⏰ **Wygaśnięcie** | Zarządzanie cyklem życia haseł (90 dni) |
| 🔄 **Rehashing** | Automatyczne upgrady algorytmu w tle |
| 🛡️ **Timing Attack Protection** | Constant-time comparison dla wrażliwych danych |
| 📊 **Analityka** | Parsowanie i analiza struktur hashów |
| 🎲 **Generowanie** | Losowe generowanie bezpiecznych haseł |

---

## 🚀 Quick Start

### 1. Rejestracja Użytkownika

```java
// Haszuj hasło przy rejestracji
String plainPassword = "MySecurePassword123!";
String passwordHash = BCryptExtended.hashPasswordSecure(plainPassword);
// Hash: $2b$12$R9h/cIPz0gi.URNNX3kh2...

// Zapisz w bazie danych
user.setPasswordHash(passwordHash);
database.save(user);
```

### 2. Logowanie Użytkownika

```java
// Weryfikuj hasło przy logowaniu
var result = BCryptExtended.checkPasswordWithDetails(
    userInputPassword,
    storedHash
);

if (result.isValid()) {
    authenticateUser();
    
    // Opcjonalnie: upgrade hasła na nowsze parametry
    if (BCryptExtended.shouldRehash(storedHash)) {
        user.setPasswordHash(
            BCryptExtended.hashPasswordSecure(userInputPassword)
        );
        database.save(user);
    }
}
```

### 3. Sprawdzenie Siły Hasła

```java
PasswordStrength strength = BCryptExtended.checkPasswordStrength(password);
// VERY_WEAK, WEAK, FAIR, GOOD, STRONG, VERY_STRONG

if (strength.score >= PasswordStrength.GOOD.score) {
    // Hasło wystarczająco silne
    registerUser(password);
}
```

### 4. Zarządzanie Wygaśnięciem

```java
// Sprawdzenie czy hasło nie wygasło
if (!BCryptExtended.isPasswordValid(user.getLastPasswordChange())) {
    user.setPasswordExpired(true);
    redirectToPasswordChange();
}

// Wyświetl ostrzeżenie gdy zostało mało dni
long daysLeft = BCryptExtended.getDaysUntilExpiry(user.getLastPasswordChange());
if (daysLeft < 7) {
    user.notifyExpiryWarning(daysLeft);
}
```

---

## 📦 Struktura Plików

```
BCryptExtended/
├── BCryptExtended.java                    # Główna implementacja
├── BCryptExtendedExamples.java             # Praktyczne przykłady
├── BCryptExtendedTest.java                  # Test działania
└── README.md                                 # Pełna dokumentacja
```

### BCryptExtended.java (1000+ linii)

Główna klasa zawierająca:

- **Sekcja Konfiguracji** - Stałe i parametry bezpieczeństwa
- **Sekcja Haszowania** - Funkcje hash/verify
- **Sekcja Walidacji** - Sprawdzenie poprawności haseł
- **Sekcja Wygaśnięcia** - Zarządzanie cyklem życia
- **Sekcja Cache'u** - Optymalizacja wydajności
- **Sekcja Formatu** - Walidacja estrutury hashów
- **Sekcja Advanced** - Zaawansowane funkcje
- **Sekcja Analizy** - Parsowanie hashów
- **Sekcja Demo** - Testy i przykłady

Każda sekcja zawiera:
- ✨ **JavaDoc** - pełna dokumentacja
- 📝 **Adnotacje** - objaśnienie każdej linii
- ⚠️ **Uwagi** - ostrzeżenia i best practices
- 🔍 **Parametry** - szczegółowy opis argumentów
- 💡 **Przypadki użycia** - praktyczne scenariusze

---

## 🔑 Kluczowe API

### Haszowanie

```java
// Z domyślnymi parametrami (12 rund, ~260ms)
String hash = BCryptExtended.hashPasswordSecure(password);

// Z custom parametrami
String hash = BCryptExtended.hashPasswordSecure(password, 14);
```

### Weryfikacja

```java
// Bezpieczna weryfikacja z obsługą błędów
var result = BCryptExtended.checkPasswordWithDetails(plaintext, hash);
if (result.isValid()) { /* OK */ }
```

### Siła Hasła

```java
PasswordStrength strength = BCryptExtended.checkPasswordStrength(password);
// Zwraca: VERY_WEAK | WEAK | FAIR | GOOD | STRONG | VERY_STRONG
```

### Wygaśnięcie

```java
// Czy hasło jest ważne?
boolean valid = BCryptExtended.isPasswordValid(lastChanged);

// Ile dni do wygaśnięcia?
long days = BCryptExtended.getDaysUntilExpiry(lastChanged);
```

### Analiza Hashów

```java
// Parsuj informacje z hasha
HashInfo info = BCryptExtended.getHashInfo(hash);
System.out.println(info.version());  // 2b
System.out.println(info.rounds());   // 12

// Czy hash wymaga upgrade'u?
if (BCryptExtended.shouldRehash(hash)) {
    String newHash = BCryptExtended.rehashPassword(plaintext, hash);
}
```

### Bezpieczne Porównanie

```java
// Zawsze używaj dla wrażliwych danych!
boolean tokensMatch = BCryptExtended.constantTimeCompare(token1, token2);
// ❌ Nigdy: token1.equals(token2)
```

### Generowanie Haseł

```java
// Bezpieczne hasło z gwarantowanymi znakami
String password = BCryptExtended.generateRandomPassword(16);
// Zawiera: wielkie, małe, cyfry, znaki specjalne
```

---

## 🛡️ Bezpieczeństwo

### ✅ Implementacja Bezpieczna Przed:

| Typ Ataku | Ochrona |
|-----------|---------|
| **Brute Force** | Exponential cost (2^12 = 4096 iteracji) |
| **Dictionary Attack** | Salt + iteracje |
| **Rainbow Table** | 22-bit salt |
| **Timing Attack** | Constant-time comparison |
| **GPU Acceleration** | Memory-hard BCrypt |
| **Side-Channel** | Implementacja z JBcrypt |

### 📋 Zgodność Standardów:

- ✅ **NIST SP 800-63B** - 8+ char minimum
- ✅ **OWASP Top 10** - Proper password handling
- ✅ **CWE-327** - Weak Cryptography
- ✅ **CWE-916** - Insufficient Computational Effort

---

## ⚡ Wydajność

### Czasy Haszowania

| Rundy | Iteracje | Czas | Zastosowanie |
|-------|----------|------|--------------|
| 4 | 2^4 | ~10ms | Demo (NIE dla prod) |
| 10 | 2^10 | ~100ms | Legacy |
| **12** | **2^12** | **~260ms** | ✅ **Rekomenduje** |
| 13 | 2^13 | ~500ms | High Security |
| 14 | 2^14 | ~1s | Very High Security |

### Zalecenia:

- **Nowe aplikacje:** 12-13 rund
- **Production:** Minimum 12 rund
- **Legacy upgrade:** Minimum 12 rund

---

## 📚 Dokumentacja

### README.md

Pełna dokumentacja techniczna zawierająca:

- 🏗️ Architektura klasy
- 📖 API Reference (szczegółowy)
- ✅ Best Practices
- 📊 Benchmarki
- 🔒 Security Considerations
- 🔧 Troubleshooting
- 💼 Integracja ze Spring Security
- 📝 Changelog

### BCryptExtendedExamples.java

Praktyczne przykłady dla:

1. **Rejestracja użytkownika** - Pełny flow
2. **Logowanie** - Weryfikacja + optional rehashing
3. **Zmiana hasła** - Z walidacją starego
4. **Reset hasła** - Generowanie tymczasowego
5. **Wygaśnięcie** - Monitoring + notifications
6. **Audit** - Analiza hashów
7. **Tokeny** - Bezpieczne porównanie

---

## 💻 Integracja

### GRADLE

```gradle
implementation("pl.qwrtyy.bcrypt-extended:SOON")
```

### Spring Security

```java
@Configuration
public class SecurityConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence raw) {
                return BCryptExtended.hashPasswordSecure(raw.toString());
            }
            
            @Override
            public boolean matches(CharSequence raw, String encoded) {
                var result = BCryptExtended.checkPasswordWithDetails(
                    raw.toString(),
                    encoded
                );
                return result.isValid();
            }
        };
    }
}
```

### JPA Entity

```java
@Entity
public class User {
    @Column(length = 60)  // BCrypt zawsze 60 znaków
    private String passwordHash;
    
    @Column(nullable = false)
    private Instant lastPasswordChanged;
    
    public boolean checkPassword(String plaintext) {
        var result = BCryptExtended.checkPasswordWithDetails(
            plaintext,
            this.passwordHash
        );
        return result.isValid();
    }
    
    public void setPassword(String plaintext) {
        this.passwordHash = BCryptExtended.hashPasswordSecure(plaintext);
        this.lastPasswordChanged = Instant.now();
    }
}
```

---

## 🎯 Przypadki Użycia

### Authentication System

```java
// Flow logowania
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    User user = findUser(req.getEmail());
    
    var result = BCryptExtended.checkPasswordWithDetails(
        req.getPassword(),
        user.getPasswordHash()
    );
    
    if (!result.isValid()) {
        recordFailedAttempt(user.getId());
        return badRequest("Invalid credentials");
    }
    
    // Upgrade na nowsze parametry
    if (BCryptExtended.shouldRehash(user.getPasswordHash())) {
        user.setPasswordHash(
            BCryptExtended.hashPasswordSecure(req.getPassword())
        );
        save(user);
    }
    
    return ok(generateJWT(user));
}
```

### Password Policy Enforcement

```java
// Walidacja przy rejestracji
@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
    try {
        BCryptExtended.validatePassword(req.getPassword());
    } catch (IllegalArgumentException e) {
        return badRequest("Hasło: " + e.getMessage());
    }
    
    PasswordStrength strength = BCryptExtended.checkPasswordStrength(
        req.getPassword()
    );
    
    if (strength.score < PasswordStrength.GOOD.score) {
        return badRequest("Password too weak: " + strength.description);
    }
    
    user.setPassword(req.getPassword());
    return ok("Registered");
}
```

### Password Expiry Management

```java
@Scheduled(fixedDelay = Duration.ofHours(1))
public void checkPasswordExpiry() {
    userRepository.findAll().forEach(user -> {
        long daysLeft = BCryptExtended.getDaysUntilExpiry(
            user.getLastPasswordChanged()
        );
        
        if (daysLeft <= 7 && daysLeft > 0) {
            notificationService.sendWarning(user, daysLeft);
        } else if (daysLeft == 0) {
            user.setPasswordExpired(true);
            userRepository.save(user);
        }
    });
}
```

---

## 🔗 Powiązane Zasoby

- [JBcrypt GitHub](https://github.com/jeremyh/jBCrypt)

---


<div align="center">

**Wersja:** 2.1  
**Status:** Production Ready ✅  
**Ostatnia aktualizacja:** 2026  

Made with ❤️ for Security

</div>
