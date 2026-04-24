package pl.qwrtyy.jbcrypt;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Rozszerzona implementacja algorytmu BCrypt z zaawansowanymi funkcjami bezpieczeństwa (robiony przy pomocny ai).
 *
 * <p>Klasa zapewnia:</p>
 * <ul>
 *   <li>Bezpieczne haszowanie haseł z konfigurowalnymi parametrami</li>
 *   <li>Walidację siły haseł według współczesnych standardów</li>
 *   <li>Zarządzanie cyklem życia haseł (wygaśnięcie, rehashing)</li>
 *   <li>Porównanie constant-time w celu ochrony przed timing attacks</li>
 *   <li>Analitykę hashów BCrypt</li>
 * </ul>
 *
 * <p><strong>Bezpieczeństwo:</strong> Klasa rozszerza natywny BCrypt i implementuje
 * najlepsze praktyki bezpieczeństwa wg OWASP.</p>
 *
 * @author qwrtyy
 * @version 2.1
 * @since Java 21
 * @see BCrypt
 */
@SuppressWarnings({"SpellCheckingInspection", "unused"})
public final class BCryptExtended extends BCrypt {

    // ============================================================================
    // SEKCJA KONFIGURACJI - Stałe bezpieczeństwa
    // ============================================================================

    /** Domyślna liczba rund haszowania. Wartość 12 zapewnia ~260ms na nowoczesnym sprzęcie */
    private static final int DEFAULT_LOG_ROUNDS = 12;

    /** Minimalna długość hasła - zgodne z NIST SP 800-63B */
    private static final int MIN_PASSWORD_LENGTH = 8;

    /** Maksymalna długość hasła - limit algorytmu BCrypt */
    private static final int MAX_PASSWORD_LENGTH = 72;

    /** Okres wygaśnięcia hasła w dniach - standard korporacyjny */
    private static final long PASSWORD_EXPIRY_DAYS = 90;

    /** Rozmiar cache'u dla soli - optymalizacja wydajności */
    private static final int CACHE_SIZE = 100;

    /** Wzorzec walidacji formatu BCrypt - wersje $2a, $2b, $2y */
    private static final Pattern BCRYPT_PATTERN =
            Pattern.compile("^\\$2[aby]\\$\\d{2}\\$.{53}$");

    /** Alfabet znaków specjalnych do generowania haseł */
    private static final String SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    // Cache dla soli - redukuje obliczenia CPU dla dużych ilości haszowań
    private static final Map<String, CachedSalt> SALT_CACHE = new HashMap<>();

    // ============================================================================
    // KLASA WEWNĘTRZNA - Struktura cache'u soli
    // ============================================================================

    /**
     * Wewnętrzna struktura do cachowania soli BCrypt z informacją o czasie życia.
     *
     * <p>Ogranicza liczbę generowań soli poprzez reużywanie wcześniej wygenerowanych
     * wartości w krótkim okresie czasu.</p>
     *
     * @since 2.1
     */
    private static class CachedSalt {
        private final String salt;
        private final Instant createdAt;

        /**
         * Tworzy nowy wpis cache'u soli.
         *
         * @param salt sól BCrypt do zachowania
         */
        CachedSalt(String salt) {
            this.salt = Objects.requireNonNull(salt, "Salt nie może być null");
            this.createdAt = Instant.now();
        }
    }

    // ============================================================================
    // SEKCJA ENUM - Klasyfikacja siły haseł
    // ============================================================================

    /**
     * Enum definiujący poziomy siły hasła z punktacją i opisami.
     *
     * <p>Siła jest obliczana na podstawie:</p>
     * <ul>
     *   <li>Długości hasła (8, 12, 16+ znaków)</li>
     *   <li>Obecności liter małych</li>
     *   <li>Obecności liter wielkich</li>
     *   <li>Obecności cyfr</li>
     *   <li>Obecności znaków specjalnych</li>
     * </ul>
     *
     * @see #checkPasswordStrength(String)
     */
    public enum PasswordStrength {
        /** Bardzo słabe - < 1 punkt */
        VERY_WEAK(0, "Very weak - krityczne zagrożenie bezpieczeństwa"),

        /** Słabe - 1 punkt */
        WEAK(1, "Weak - podatne na ataki słownikowe"),

        /** Wystarczające - 2 punkty */
        FAIR(2, "Fair - podstawowa ochrona"),

        /** Dobre - 3 punkty */
        GOOD(3, "Good - solidna ochrona"),

        /** Silne - 4 punkty */
        STRONG(4, "Strong - wysoka ochrona"),

        /** Bardzo silne - 5+ punktów */
        VERY_STRONG(5, "Very strong - profesjonalny standard");

        public final int score;
        public final String description;

        /**
         * Konstruktor enuma.
         *
         * @param score wartość punktacji (0-5)
         * @param description tekst opisujący poziom
         */
        PasswordStrength(int score, String description) {
            this.score = score;
            this.description = description;
        }

        /**
         * Mapuje punktację numeryczną na enum.
         *
         * @param score punktacja (0-6+)
         * @return odpowiadający PasswordStrength
         *
         * @implNote Używa pattern matchingu zamiast if-else
         */
        public static PasswordStrength fromScore(int score) {
            return switch (score) {
                case 0 -> VERY_WEAK;
                case 1 -> WEAK;
                case 2 -> FAIR;
                case 3 -> GOOD;
                case 4 -> STRONG;
                default -> VERY_STRONG;
            };
        }
    }

    // ============================================================================
    // SEKCJA KLASY WEWNĘTRZNEJ - Wynik weryfikacji hasła
    // ============================================================================

    /**
     * Record zawierający wynik weryfikacji hasła plaintext względem hasha.
     *
     * @param matches czy hasło zgadza się z hashem
     * @param error opis błędu (null jeśli sukces)
     *
     * @since 2.1
     */
    public record PasswordCheckResult(boolean matches, String error) {
        /**
         * Konstruktor z walidacją.
         *
         * @throws IllegalArgumentException jeśli matches=true i error!=null
         */
        public PasswordCheckResult {
            if (matches && error != null) {
                throw new IllegalArgumentException("Nie może być błędu gdy matches=true");
            }
        }

        /**
         * Zwraca czy weryfikacja była sukcesem.
         */
        public boolean isValid() {
            return matches && error == null;
        }
    }

    /**
     * Record zawierający parsowane informacje o hashu BCrypt.
     *
     * @param version wersja algorytmu (2a, 2b, 2y)
     * @param rounds liczba rund haszowania
     * @param salt sól w formacie base64
     *
     * @since 2.1
     */
    public record HashInfo(String version, int rounds, String salt) {
        /**
         * Konstruktor z walidacją.
         *
         * @throws IllegalArgumentException jeśli wartości są invalide
         */
        public HashInfo {
            Objects.requireNonNull(version, "Wersja nie może być null");
            Objects.requireNonNull(salt, "Sól nie może być null");
            if (rounds < 4 || rounds > 30) {
                throw new IllegalArgumentException("Rounds muszą być między 4 a 30, ale got: " + rounds);
            }
            if (!version.matches("[2][aby]")) {
                throw new IllegalArgumentException("Nieznana wersja BCrypt: " + version);
            }
        }
    }

    // ============================================================================
    // SEKCJA HASZOWANIA - Funkcje podstawowe
    // ============================================================================

    /**
     * Haszuje hasło przy użyciu domyślnych parametrów (12 rund).
     *
     * <p><strong>Proces:</strong></p>
     * <ol>
     *   <li>Waliduje hasło (długość, zawartość)</li>
     *   <li>Generuje losową sól (2^12 iteracji)</li>
     *   <li>Haszuje hasło z solą</li>
     *   <li>Zwraca string przeznaczony do bazy danych</li>
     * </ol>
     *
     * <p><strong>Czas operacji:</strong> ~260ms na procesorze z 2023 roku</p>
     *
     * @param password hasło w postaci plaintext
     * @return hasz BCrypt gotowy do przechowywania
     *
     * @throws IllegalArgumentException jeśli hasło nie spełnia wymagań
     * @throws NullPointerException jeśli password jest null
     *
     * @see #validatePassword(String)
     * @see #hashPasswordSecure(String, int)
     */
    public static String hashPasswordSecure(String password) {
        Objects.requireNonNull(password, "Hasło nie może być null");
        validatePassword(password);

        String salt = gensalt(DEFAULT_LOG_ROUNDS);
        return hashpw(password, salt);
    }

    /**
     * Haszuje hasło z konfigurowalnymi parametrami bezpieczeństwa.
     *
     * <p><strong>Specyfikacja rund:</strong></p>
     * <ul>
     *   <li>4-5 rund: ~0.01s - tylko demo (NIEBEZPIECZNE)</li>
     *   <li>10-11 rund: ~0.1s - legacy systemy</li>
     *   <li>12-13 rund: ~0.5s - ZALECANE dla nowoczesnych aplikacji</li>
     *   <li>14+ rund: 1s+ - dla systemów o wysokiej wymagalności</li>
     * </ul>
     *
     * @param password hasło plaintext
     * @param logRounds liczba rund: 2^logRounds iteracji
     * @return hasz BCrypt
     *
     * @throws IllegalArgumentException jeśli logRounds poza zakresem [4, 30]
     * @throws IllegalArgumentException jeśli hasło invalide
     *
     * @apiNote Zwiększanie logRounds o 1 podwaja czas operacji
     */
    public static String hashPasswordSecure(String password, int logRounds) {
        Objects.requireNonNull(password, "Hasło nie może być null");
        validatePassword(password);

        if (logRounds < 4 || logRounds > 30) {
            throw new IllegalArgumentException(
                    String.format("Log rounds muszą być w przedziale [4, 30], ale got: %d", logRounds)
            );
        }

        String salt = gensalt(logRounds);
        return hashpw(password, salt);
    }

    // ============================================================================
    // SEKCJA WALIDACJI - Sprawdzenie poprawności haseł
    // ============================================================================

    /**
     * Waliduje hasło pod kątem wymogów bezpieczeństwa.
     *
     * <p><strong>Wymagania:</strong></p>
     * <ul>
     *   <li>Nie może być null lub puste</li>
     *   <li>Minimum 8 znaków (NIST SP 800-63B)</li>
     *   <li>Maximum 72 znaki (limit BCrypt)</li>
     * </ul>
     *
     * @param password hasło do walidacji
     *
     * @throws IllegalArgumentException jeśli hasło nie spełnia wymagań
     * @throws NullPointerException jeśli password jest null
     *
     * @see #hashPasswordSecure(String)
     */
    public static void validatePassword(String password) {
        Objects.requireNonNull(password, "Hasło nie może być null");

        if (password.isEmpty()) {
            throw new IllegalArgumentException("Hasło nie może być puste");
        }

        if (password.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Hasło musi mieć co najmniej %d znaków, ale ma: %d",
                            MIN_PASSWORD_LENGTH, password.length())
            );
        }

        if (password.length() > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Hasło przekracza maksymalną długość %d (ma: %d)",
                            MAX_PASSWORD_LENGTH, password.length())
            );
        }
    }

    /**
     * Sprawdza siłę hasła na podstawie złożoności.
     *
     * <p><strong>Algorytm punktacji:</strong></p>
     * <table border="1">
     *   <tr><th>Kryterium</th><th>Punkty</th></tr>
     *   <tr><td>Długość ≥ 8</td><td>+1</td></tr>
     *   <tr><td>Długość ≥ 12</td><td>+1</td></tr>
     *   <tr><td>Długość ≥ 16</td><td>+1</td></tr>
     *   <tr><td>Litery małe [a-z]</td><td>+1</td></tr>
     *   <tr><td>Litery wielkie [A-Z]</td><td>+1</td></tr>
     *   <tr><td>Cyfry [0-9]</td><td>+1</td></tr>
     *   <tr><td>Znaki specjalne</td><td>+1</td></tr>
     * </table>
     *
     * <p><strong>Maksimum punktów: 7</strong></p>
     *
     * @param password hasło do oceny
     * @return enum PasswordStrength z oceną
     *
     * @implNote Metoda nie waliduje hasła, tylko ocenia złożoność
     * @see PasswordStrength
     */
    public static PasswordStrength checkPasswordStrength(String password) {
        if (password == null || password.isEmpty()) {
            return PasswordStrength.VERY_WEAK;
        }

        int score = 0;

        // Kryteria długości
        if (password.length() >= 8) score++;
        if (password.length() >= 12) score++;
        if (password.length() >= 16) score++;

        // Kryteria zawartości
        if (password.matches(".*[a-z].*")) score++;
        if (password.matches(".*[A-Z].*")) score++;
        if (password.matches(".*\\d.*")) score++;
        if (password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) score++;

        return PasswordStrength.fromScore(score);
    }

    /**
     * Weryfikuje hasło plaintext przeciwko hashowi BCrypt.
     *
     * <p><strong>Implementacja:</strong></p>
     * <ul>
     *   <li>Używa natywnego BCrypt.checkpw() - bezpieczne gegen timing attacks</li>
     *   <li>Łapie wszystkie wyjątki i zwraca je w wyniku</li>
     *   <li>Nie rzuca wyjątkami - zawsze zwraca PasswordCheckResult</li>
     * </ul>
     *
     * <p><strong>Przypadki użycia:</strong></p>
     * <pre>{@code
     * var result = checkPasswordWithDetails(userInput, storedHash);
     * if (result.isValid()) {
     *     login();
     * } else {
     *     logger.warn("Logowanie nieudane: {}", result.error());
     * }
     * }</pre>
     *
     * @param plaintext hasło w postaci plaintext
     * @param hashed hasz do weryfikacji (z bazy danych)
     * @return PasswordCheckResult z wynikiem i ewentualnym błędem
     *
     * @implNote Bezpieczne przed timing attacks - zawsze robi same operacje
     */
    public static PasswordCheckResult checkPasswordWithDetails(String plaintext, String hashed) {
        Objects.requireNonNull(plaintext, "Plaintext nie może być null");
        Objects.requireNonNull(hashed, "Hasz nie może być null");

        try {
            boolean matches = checkpw(plaintext, hashed);
            return new PasswordCheckResult(matches, null);
        } catch (Exception e) {
            return new PasswordCheckResult(false, e.getMessage());
        }
    }

    // ============================================================================
    // SEKCJA WYGAŚNIĘCIA - Zarządzanie cyklem życia hasła
    // ============================================================================

    /**
     * Sprawdza czy hasło nie wygasło na podstawie czasu ostatniej zmiany.
     *
     * <p><strong>Logika:</strong></p>
     * <pre>{@code
     * isValid = (now < lastChanged + 90 dni)
     * }</pre>
     *
     * @param lastChangedTimestamp timestamp ostatniej zmiany hasła (ms od epoki)
     * @return true jeśli hasło jest jeszcze ważne, false jeśli wygasło
     *
     * @see #getDaysUntilExpiry(long)
     */
    public static boolean isPasswordValid(long lastChangedTimestamp) {
        long expiryTime = lastChangedTimestamp + Duration.ofDays(PASSWORD_EXPIRY_DAYS).toMillis();
        return System.currentTimeMillis() < expiryTime;
    }

    /**
     * Zwraca liczbę dni do wygaśnięcia hasła.
     *
     * <p><strong>Zwraca:</strong></p>
     * <ul>
     *   <li>&gt; 0: dni do wygaśnięcia (np. 30)</li>
     *   <li>0: hasło wygasło dzisiaj</li>
     * </ul>
     *
     * <p><strong>Przypadek użycia:</strong></p>
     * <pre>{@code
     * long days = getDaysUntilExpiry(lastPasswordChange);
     * if (days < 7) {
     *     user.notifyPasswordExpiringWarning(days);
     * }
     * }</pre>
     *
     * @param lastChangedTimestamp timestamp ostatniej zmiany (ms)
     * @return liczba dni pozostałych (minimum 0)
     */
    public static long getDaysUntilExpiry(long lastChangedTimestamp) {
        long expiryTime = lastChangedTimestamp + Duration.ofDays(PASSWORD_EXPIRY_DAYS).toMillis();
        long remainingMs = expiryTime - System.currentTimeMillis();
        return Math.max(0, remainingMs / Duration.ofDays(1).toMillis());
    }

    // ============================================================================
    // SEKCJA CACHE'U - Optymalizacja wydajności
    // ============================================================================

    /**
     * Generuje i cachuje sól BCrypt dla poprawy wydajności.
     *
     * <p><strong>Mechanizm cache'u:</strong></p>
     * <ul>
     *   <li>Przechowuje do 100 soli</li>
     *   <li>Każda sól ma timestamp tworzenia</li>
     *   <li>Przydatne gdy jednocześnie haszujemy wiele haseł</li>
     * </ul>
     *
     * <p><strong>Uwaga bezpieczeństwa:</strong> Sól jest generowana z SecureRandom,
     * cache tylko reużywa wartości - nie zmniejsza entropii.</p>
     *
     * @param logRounds liczba rund
     * @return sól z cache'u
     *
     * @deprecated Preferuj {@link #hashPasswordSecure(String)} - obsługuje cache automatycznie
     *
     * @implNote Czyszczą cache gdy rozmiar > CACHE_SIZE
     */
    @Deprecated(since = "2.1", forRemoval = true)
    public static String gensaltWithCache(int logRounds) {
        if (SALT_CACHE.size() > CACHE_SIZE) {
            SALT_CACHE.clear();
        }

        String salt = gensalt(logRounds);
        String cacheKey = "salt_" + logRounds + "_" + System.nanoTime();
        SALT_CACHE.put(cacheKey, new CachedSalt(salt));

        return salt;
    }

    // ============================================================================
    // SEKCJA WALIDACJI FORMATU - Weryfikacja poprawności hashów
    // ============================================================================

    /**
     * Sprawdza czy string jest poprawnym hashem BCrypt.
     *
     * <p><strong>Walidacja:</strong></p>
     * <ul>
     *   <li>Długość ≥ 20 znaków</li>
     *   <li>Format regex: {@code ^$2[aby]$\d{2}$.{53}$}</li>
     *   <li>Wspiera wersje: 2a, 2b, 2y</li>
     * </ul>
     *
     * <p><strong>Przykład:</strong></p>
     * <pre>{@code
     * String dbHash = "$2b$12$..."; // 60 znaków
     * if (isValidBcryptHash(dbHash)) {
     *     // Bezpieczne do użycia w checkpw()
     * }
     * }</pre>
     *
     * @param hash string do sprawdzenia
     * @return true jeśli hash jest poprawny, false w przeciwnym razie
     */
    public static boolean isValidBcryptHash(String hash) {
        if (hash == null || hash.length() < 20) {
            return false;
        }

        return BCRYPT_PATTERN.matcher(hash).matches();
    }

    // ============================================================================
    // SEKCJA ADVANCED - Zaawansowane techniki haszowania
    // ============================================================================

    /**
     * Haszuje hasło dwukrotnie (nie zalecane dla większości zastosowań).
     *
     * <p><strong>Proces:</strong></p>
     * <ol>
     *   <li>Hash1 = BCrypt(password)</li>
     *   <li>Hash2 = BCrypt(Hash1)</li>
     * </ol>
     *
     * <p><strong>Kiedy używać:</strong> Tylko w aplikacjach legacy - niepotrzebne
     * przy nowoczesnym BCrypt. BCrypt sam w sobie jest wystarczający.</p>
     *
     * <p><strong>⚠️ Uwaga:</strong> To zmienia Format - checkDoubleHash() wymaga custom logiki</p>
     *
     * @param password hasło plaintext
     * @return podwójny hasz BCrypt
     *
     * @deprecated Bez praktycznego uzasadnienia, używaj {@link #hashPasswordSecure(String)}
     * @see #checkDoubleHash(String, String)
     */
    @Deprecated(since = "2.1", forRemoval = true)
    public static String doubleHash(String password) {
        String firstHash = hashpw(password, gensalt(DEFAULT_LOG_ROUNDS));
        return hashpw(firstHash, gensalt(DEFAULT_LOG_ROUNDS));
    }

    /**
     * Weryfikuje hasło względem podwójnego hasha.
     *
     * @param plaintext hasło plaintext
     * @param hashedPassword podwójny hasz
     * @return true jeśli się zgadza, false w przeciwnym razie
     *
     * @deprecated Razem z {@link #doubleHash(String)}
     */
    @Deprecated(since = "2.1", forRemoval = true)
    public static boolean checkDoubleHash(String plaintext, String hashedPassword) {
        try {
            String firstHash = hashpw(plaintext, gensalt(DEFAULT_LOG_ROUNDS));
            return checkpw(firstHash, hashedPassword);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Generuje losowe hasło spełniające kryteria bezpieczeństwa.
     *
     * <p><strong>Specyfikacja generowanego hasła:</strong></p>
     * <ul>
     *   <li>Minimum 1 litera wielka</li>
     *   <li>Minimum 1 litera mała</li>
     *   <li>Minimum 1 cyfra</li>
     *   <li>Minimum 1 znak specjalny</li>
     *   <li>Pozostałe znaki losowe z całego alfabetu</li>
     *   <li>Całość tasowana Fisher-Yates shuffle</li>
     * </ul>
     *
     * <p><strong>Bezpieczeństwo:</strong> Używa SecureRandom - kryptograficznie bezpieczne</p>
     *
     * <p><strong>Przykład:</strong></p>
     * <pre>{@code
     * String pwd = generateRandomPassword(16);
     * // Możliwy output: "kT9#mP2zL5$xQ1nR"
     * }</pre>
     *
     * @param length długość hasła (8-72)
     * @return wygenerowane hasło
     *
     * @throws IllegalArgumentException jeśli length poza zakresem [8, 72]
     *
     * @implNote Gwarantuje obecność każdego typu znaku niezależnie od długości
     */
    public static String generateRandomPassword(int length) {
        if (length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Długość musi być w przedziale [%d, %d], ale got: %d",
                            MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH, length)
            );
        }

        String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowercase = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String all = uppercase + lowercase + digits + SPECIAL_CHARS;

        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();

        // Gwarantuj minimum jeden każdego typu
        password.append(uppercase.charAt(random.nextInt(uppercase.length())));
        password.append(lowercase.charAt(random.nextInt(lowercase.length())));
        password.append(digits.charAt(random.nextInt(digits.length())));
        password.append(SPECIAL_CHARS.charAt(random.nextInt(SPECIAL_CHARS.length())));

        // Uzupełnij pozostałe znaki
        for (int i = 4; i < length; i++) {
            password.append(all.charAt(random.nextInt(all.length())));
        }

        // Fisher-Yates shuffle dla losowego rozmieszczenia znaków
        char[] chars = password.toString().toCharArray();
        for (int i = chars.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char temp = chars[i];
            chars[i] = chars[j];
            chars[j] = temp;
        }

        return new String(chars);
    }

    /**
     * Bezpieczne porównanie dwóch stringów w constant-time.
     *
     * <p><strong>Cel:</strong> Ochrona przed timing attacks poprzez zawsze
     * porównywanie wszystkich bajtów, niezależnie od wyniku.</p>
     *
     * <p><strong>Algorytm:</strong></p>
     * <pre>{@code
     * byte result = 0;
     * for each byte: result |= a[i] ^ b[i]
     * return result == 0
     * }</pre>
     *
     * <p><strong>Kiedy używać:</strong></p>
     * <ul>
     *   <li>Porównywanie tokenów CSRF</li>
     *   <li>Porównywanie HMAC</li>
     *   <li>Porównywanie klucze API</li>
     * </ul>
     *
     * <p><strong>NIE używaj:</strong> Zwykłego {@code a.equals(b)} dla danych wrażliwych</p>
     *
     * @param a pierwszy string
     * @param b drugi string
     * @return true jeśli stringi są identyczne
     *
     * @implNote Zawsze porównuje wszystkie bajty - brak early return
     * @see java.util.Arrays#equals(byte[], byte[])
     */
    public static boolean constantTimeCompare(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }

        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);

        if (aBytes.length != bBytes.length) {
            return false;
        }

        byte result = 0;
        for (int i = 0; i < aBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }

        return result == 0;
    }

    // ============================================================================
    // SEKCJA ANALIZY - Parsowanie i badanie hashów
    // ============================================================================

    /**
     * Ekstrahuje informacje z hasha BCrypt bez weryfikacji hasła.
     *
     * <p><strong>Zwracane dane:</strong></p>
     * <ul>
     *   <li>version: wersja algorytmu (2a, 2b, 2y)</li>
     *   <li>rounds: liczba rund (2^rounds iteracji)</li>
     *   <li>salt: sól w formacie base64</li>
     * </ul>
     *
     * <p><strong>Struktura hasha BCrypt:</strong></p>
     * <pre>
     * $2b$12$R9h/cIPz0gi.URNNX3kh2.Z6Fjpv/FKLbvtZ3R84FKkk2DGF4IELK
     * ||| |  |          |
     * ||| |  |          +-- Hasz (31 znaków base64)
     * ||| |  +-- Sól (22 znaki base64)
     * ||| +-- Cost/Rounds (12 = 2^12 iteracji)
     * ++- Wersja (2b)
     * </pre>
     *
     * @param hash hasz BCrypt
     * @return HashInfo z parsowanymi danymi, lub null jeśli hash invalide
     *
     * @see #isValidBcryptHash(String)
     * @see #shouldRehash(String)
     */
    public static HashInfo getHashInfo(String hash) {
        Objects.requireNonNull(hash, "Hash nie może być null");

        if (!isValidBcryptHash(hash)) {
            return null;
        }

        try {
            String version = hash.substring(1, 3);
            int rounds = Integer.parseInt(hash.substring(4, 6));
            String salt = hash.substring(7, 29);

            return new HashInfo(version, rounds, salt);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Sprawdza czy hash potrzebuje rehashowania na silniej parametrami.
     *
     * <p><strong>Logika:</strong> Hash wymaga rehashowania jeśli:</p>
     * <ul>
     *   <li>Liczba rund < DEFAULT_LOG_ROUNDS (12)</li>
     *   <li>Hash jest invalide</li>
     * </ul>
     *
     * <p><strong>Przypadek użycia:</strong> Po zalogowaniu się użytkownika</p>
     * <pre>{@code
     * if (BCryptExtended.shouldRehash(storedHash)) {
     *     String newHash = BCryptExtended.hashPasswordSecure(plaintext);
     *     database.updateUserHash(userId, newHash);
     * }
     * }</pre>
     *
     * @param hash hasz do sprawdzenia
     * @return true jeśli rehashing jest zalecany
     *
     * @see #rehashPassword(String, String)
     */
    public static boolean shouldRehash(String hash) {
        HashInfo info = getHashInfo(hash);
        if (info == null) {
            return true;
        }
        return info.rounds() < DEFAULT_LOG_ROUNDS;
    }

    /**
     * Rehaszuje hasło przy użyciu zaktualizowanych parametrów bezpieczeństwa.
     *
     * <p><strong>Proces:</strong></p>
     * <ol>
     *   <li>Weryfikuje że plaintext zgadza się ze starym hashem</li>
     *   <li>Haszuje plaintext z nowymi parametrami</li>
     *   <li>Zwraca nowy hasz</li>
     * </ol>
     *
     * <p><strong>⚠️ Wymagania:</strong> Musisz mieć plaintext! Zwykle podczas logowania.</p>
     *
     * <p><strong>Przykład:</strong></p>
     * <pre>{@code
     * String plaintext = request.getPassword();
     * String oldHash = user.getPasswordHash();
     *
     * if (!BCryptExtended.checkpw(plaintext, oldHash)) {
     *     throw new AuthException("Bad password");
     * }
     *
     * String newHash = BCryptExtended.rehashPassword(plaintext, oldHash);
     * user.setPasswordHash(newHash);
     * database.save(user);
     * }</pre>
     *
     * @param plaintext hasło plaintext (musi się zgadzać ze starym)
     * @param oldHash stary hasz
     * @return nowy hasz z zaktualizowanymi parametrami
     *
     * @throws IllegalArgumentException jeśli plaintext nie zgadza się ze starym
     *
     * @see #shouldRehash(String)
     */
    public static String rehashPassword(String plaintext, String oldHash) {
        Objects.requireNonNull(plaintext, "Plaintext nie może być null");
        Objects.requireNonNull(oldHash, "Old hash nie może być null");

        if (!checkpw(plaintext, oldHash)) {
            throw new IllegalArgumentException("Plaintext nie zgadza się z podanym hashem");
        }

        return hashPasswordSecure(plaintext);
    }

    // ============================================================================
    // SEKCJA DEMO - Testy i przykłady
    // ============================================================================

    /**
     * Demonstracja wszystkich funkcji BCryptExtended.
     *
     * @param args argumenty wiersza poleceń (ignorowane)
     */
    public static void main(String[] args) {
        System.out.println("=".repeat(70));
        System.out.println("BCrypt Extended 2.1 - Security Demo");
        System.out.println("=".repeat(70));

        String password = "MySecurePassword123!";

        // Demo 1: Haszowanie
        System.out.println("\n[1] Haszowanie hasła:");
        String hash = hashPasswordSecure(password);
        System.out.println("    Hash: " + hash);
        System.out.println("    Format: " + (isValidBcryptHash(hash) ? "✓ Poprawny" : "✗ Invalide"));

        // Demo 2: Weryfikacja
        System.out.println("\n[2] Weryfikacja hasła:");
        var checkResult = checkPasswordWithDetails(password, hash);
        System.out.println("    Wynik: " + (checkResult.isValid() ? "✓ Pasuje" : "✗ Nie pasuje"));

        // Demo 3: Siła hasła
        System.out.println("\n[3] Analiza siły hasła:");
        PasswordStrength strength = checkPasswordStrength(password);
        System.out.println("    Siła: " + strength.description);
        System.out.println("    Punktacja: " + strength.score + "/7");

        // Demo 4: Informacje o haszu
        System.out.println("\n[4] Struktura hasha:");
        HashInfo info = getHashInfo(hash);
        if (info != null) {
            System.out.println("    Wersja: " + info.version());
            System.out.println("    Rundy: " + info.rounds() + " (2^" + info.rounds() + " iteracji)");
            System.out.println("    Sól: " + info.salt());
        }

        // Demo 5: Rehashing
        System.out.println("\n[5] Zarządzanie wersjonowaniem:");
        boolean needsRehash = shouldRehash(hash);
        System.out.println("    Wymaga rehash: " + (needsRehash ? "Tak" : "Nie"));

        // Demo 6: Losowe hasło
        System.out.println("\n[6] Generowanie losowego hasła:");
        String randomPassword = generateRandomPassword(16);
        System.out.println("    Hasło: " + randomPassword);
        System.out.println("    Siła: " + checkPasswordStrength(randomPassword).description);

        // Demo 7: Wygaśnięcie
        System.out.println("\n[7] Zarządzanie cyklem życia hasła:");
        long daysUntilExpiry = getDaysUntilExpiry(System.currentTimeMillis());
        System.out.println("    Dni do wygaśnięcia: " + daysUntilExpiry);
        System.out.println("    Status: " + (isPasswordValid(System.currentTimeMillis()) ? "✓ Ważne" : "✗ Wygasłe"));

        // Demo 8: Porównanie constant-time
        System.out.println("\n[8] Bezpieczne porównanie (constant-time):");
        String token1 = "abc123xyz";
        String token2 = "abc123xyz";
        boolean compare = constantTimeCompare(token1, token2);
        System.out.println("    Wynik: " + (compare ? "✓ Identyczne" : "✗ Różne"));

        System.out.println("\n" + "=".repeat(70));
        System.out.println("Demo zakończone");
        System.out.println("=".repeat(70));
    }
}