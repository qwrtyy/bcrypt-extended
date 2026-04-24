package pl.qwrtyy.jbcrypt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Testy JUnit dla BCryptExtended.
 *
 * <p><strong>Zakres testów:</strong></p>
 * <ul>
 *   <li>Haszowanie haseł</li>
 *   <li>Weryfikacja haseł</li>
 *   <li>Walidacja siły haseł</li>
 *   <li>Wygaśnięcie haseł</li>
 *   <li>Analiza hashów</li>
 *   <li>Porównanie constant-time</li>
 * </ul>
 *
 * @author Security Team
 * @since 2.1
 */
@DisplayName("BCryptExtended Security Tests")
public class BCryptExtendedTest {

    // ============================================================================
    // SEKCJA 1: Testy Haszowania
    // ============================================================================

    @Test
    @DisplayName("Hasuje hasło z domyślnymi parametrami")
    void testHashPasswordSecureDefault() {
        String password = "MySecurePassword123!";

        String hash = BCryptExtended.hashPasswordSecure(password);

        assertNotNull(hash, "Hash nie powinien być null");
        assertEquals(60, hash.length(), "BCrypt hash zawsze 60 znaków");
        assertTrue(hash.startsWith("$2b$"), "Hash powinien zaczynać się od $2b$");
        assertFalse(password.equals(hash), "Hash != plaintext");
    }

    @Test
    @DisplayName("Hasuje hasło z custom parametrami")
    void testHashPasswordSecureCustomRounds() {
        String password = "TestPassword123";

        String hash4 = BCryptExtended.hashPasswordSecure(password, 4);
        String hash12 = BCryptExtended.hashPasswordSecure(password, 12);
        String hash14 = BCryptExtended.hashPasswordSecure(password, 14);

        assertNotEquals(hash4, hash12, "Różne rundy = różne hashe");
        assertNotEquals(hash12, hash14, "Różne rundy = różne hashe");

        // Wszystkie mają prawidłowy format
        assertTrue(BCryptExtended.isValidBcryptHash(hash4));
        assertTrue(BCryptExtended.isValidBcryptHash(hash12));
        assertTrue(BCryptExtended.isValidBcryptHash(hash14));
    }

    @Test
    @DisplayName("Odrzuca invalid log_rounds")
    void testHashPasswordInvalidRounds() {
        String password = "TestPassword123";

        // Poniżej minimum
        assertThrows(IllegalArgumentException.class, () ->
                        BCryptExtended.hashPasswordSecure(password, 3),
                "Powinno rzucić dla rounds < 4"
        );

        // Powyżej maksimum
        assertThrows(IllegalArgumentException.class, () ->
                        BCryptExtended.hashPasswordSecure(password, 31),
                "Powinno rzucić dla rounds > 30"
        );
    }

    @Test
    @DisplayName("Hasz jest non-deterministic (różne soli)")
    void testHashNonDeterministic() {
        String password = "SamePassword";

        String hash1 = BCryptExtended.hashPasswordSecure(password);
        String hash2 = BCryptExtended.hashPasswordSecure(password);

        assertNotEquals(hash1, hash2, "Różne hashe dla tego samego hasła");

        // Ale oba powinny verify
        assertTrue(BCryptExtended.checkpw(password, hash1));
        assertTrue(BCryptExtended.checkpw(password, hash2));
    }

    // ============================================================================
    // SEKCJA 2: Testy Walidacji Hasła
    // ============================================================================

    @Test
    @DisplayName("Waliduje minimalną długość")
    void testValidatePasswordMinLength() {
        assertThrows(IllegalArgumentException.class, () ->
                        BCryptExtended.validatePassword("Short!1"),  // 7 znaków
                "Powinno odrzucić hasło < 8 znaków"
        );

        // Akceptuje dokładnie 8
        assertDoesNotThrow(() ->
                BCryptExtended.validatePassword("ValidPass1!")
        );
    }

    @Test
    @DisplayName("Waliduje maksymalną długość")
    void testValidatePasswordMaxLength() {
        String tooLong = "a".repeat(73);  // 73 znaki

        assertThrows(IllegalArgumentException.class, () ->
                        BCryptExtended.validatePassword(tooLong),
                "Powinno odrzucić hasło > 72 znaki"
        );

        // Akceptuje dokładnie 72
        String maxValid = "a".repeat(72);
        assertDoesNotThrow(() ->
                BCryptExtended.validatePassword(maxValid)
        );
    }

    @Test
    @DisplayName("Odrzuca null i puste hasła")
    void testValidatePasswordNullEmpty() {
        assertThrows(NullPointerException.class, () ->
                        BCryptExtended.validatePassword(null),
                "Powinno rzucić dla null"
        );

        assertThrows(IllegalArgumentException.class, () ->
                        BCryptExtended.validatePassword(""),
                "Powinno rzucić dla pustego"
        );
    }

    // ============================================================================
    // SEKCJA 3: Testy Weryfikacji Hasła
    // ============================================================================

    @Test
    @DisplayName("Weryfikuje poprawne hasło")
    void testCheckPasswordCorrect() {
        String password = "MyPassword123!@#";
        String hash = BCryptExtended.hashPasswordSecure(password);

        var result = BCryptExtended.checkPasswordWithDetails(password, hash);

        assertTrue(result.isValid(), "Hasło powinno być poprawne");
        assertTrue(result.matches(), "matches powinny być true");
        assertNull(result.error(), "error powinien być null");
    }

    @Test
    @DisplayName("Odrzuca niepoprawne hasło")
    void testCheckPasswordIncorrect() {
        String password = "MyPassword123!@#";
        String hash = BCryptExtended.hashPasswordSecure(password);

        var result = BCryptExtended.checkPasswordWithDetails("WrongPassword", hash);

        assertFalse(result.isValid(), "Hasło powinno być niepoprawne");
        assertFalse(result.matches(), "matches powinny być false");
        assertNull(result.error(), "Brak błędu - po prostu nie pasuje");
    }

    @Test
    @DisplayName("Obsługuje invalide hashe gracefully")
    void testCheckPasswordInvalidHash() {
        var result = BCryptExtended.checkPasswordWithDetails("password", "invalid_hash");

        assertFalse(result.isValid(), "Result powinien być invalid");
        assertFalse(result.matches(), "matches powinny być false");
        assertNotNull(result.error(), "error nie powinien być null");
    }

    // ============================================================================
    // SEKCJA 4: Testy Siły Hasła
    // ============================================================================

    @Test
    @DisplayName("Ocenia bardzo słabe hasła")
    void testPasswordStrengthVeryWeak() {
        var strength = BCryptExtended.checkPasswordStrength("");
        assertEquals(BCryptExtended.PasswordStrength.VERY_WEAK, strength);

        strength = BCryptExtended.checkPasswordStrength(null);
        assertEquals(BCryptExtended.PasswordStrength.VERY_WEAK, strength);
    }

    @Test
    @DisplayName("Ocenia słabe hasła")
    void testPasswordStrengthWeak() {
        // Tylko 1 punkt (długość)
        var strength = BCryptExtended.checkPasswordStrength("aaaaaaaa");
        assertEquals(BCryptExtended.PasswordStrength.WEAK, strength);
    }

    @Test
    @DisplayName("Ocenia dobre hasła")
    void testPasswordStrengthGood() {
        // 8+ chars, lowercase, uppercase, digits, special
        var strength = BCryptExtended.checkPasswordStrength("MyPass123!");
        assertTrue(strength.score >= BCryptExtended.PasswordStrength.GOOD.score);
    }

    @Test
    @DisplayName("Ocenia bardzo silne hasła")
    void testPasswordStrengthVeryStrong() {
        // 16+ chars + wszystkie komponenty
        var strength = BCryptExtended.checkPasswordStrength("MySecurePassword123!@#");
        assertEquals(BCryptExtended.PasswordStrength.VERY_STRONG, strength);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "aaaaaaaa",           // Tylko lowercase
            "AAAAAAAA",           // Tylko uppercase
            "12345678",           // Tylko digits
            "aaaabbbb",           // Tylko lowercase
            "AaBbCcDd",           // Lower + upper
    })
    @DisplayName("Ocenia warianty siły haseł")
    void testPasswordStrengthVariations(String password) {
        var strength = BCryptExtended.checkPasswordStrength(password);
        assertNotNull(strength, "Strength nie powinny być null dla: " + password);
        assertTrue(strength.score >= 0, "Score powinny być >= 0");
    }

    // ============================================================================
    // SEKCJA 5: Testy Wygaśnięcia Hasła
    // ============================================================================

    @Test
    @DisplayName("Nowe hasło nie jest wygasłe")
    void testPasswordValidNew() {
        long now = System.currentTimeMillis();

        boolean valid = BCryptExtended.isPasswordValid(now);

        assertTrue(valid, "Nowe hasło powinno być ważne");
    }

    @Test
    @DisplayName("Stare hasło (100 dni) jest wygasłe")
    void testPasswordValidOld() {
        long hundredDaysAgo = System.currentTimeMillis() - (100 * 24 * 60 * 60 * 1000L);

        boolean valid = BCryptExtended.isPasswordValid(hundredDaysAgo);

        assertFalse(valid, "Hasło sprzed 100 dni powinno być wygasłe");
    }

    @Test
    @DisplayName("Oblicza dni do wygaśnięcia")
    void testGetDaysUntilExpiry() {
        long now = System.currentTimeMillis();

        long daysLeft = BCryptExtended.getDaysUntilExpiry(now);

        assertTrue(daysLeft >= 85 && daysLeft <= 90,
                "Dni do wygaśnięcia powinny być między 85-90 (got: " + daysLeft + ")");
    }

    @Test
    @DisplayName("Zwraca 0 dla wygasłych haseł")
    void testGetDaysUntilExpiryExpired() {
        long hundredDaysAgo = System.currentTimeMillis() - (100 * 24 * 60 * 60 * 1000L);

        long days = BCryptExtended.getDaysUntilExpiry(hundredDaysAgo);

        assertEquals(0, days, "Wygasłe hasło powinno zwrócić 0 dni");
    }

    // ============================================================================
    // SEKCJA 6: Testy Walidacji Formatu
    // ============================================================================

    @Test
    @DisplayName("Waliduje poprawny BCrypt hash")
    void testIsValidBcryptHashValid() {
        String validHash = "$2b$12$R9h/cIPz0gi.URNNX3kh2.Z6Fjpv/FKLbvtZ3R84FKkk2DGF4IELK";

        assertTrue(BCryptExtended.isValidBcryptHash(validHash),
                "Powinno zaakceptować prawidłowy hash");
    }

    @Test
    @DisplayName("Odrzuca null, puste, krótkie hashe")
    void testIsValidBcryptHashInvalid() {
        assertFalse(BCryptExtended.isValidBcryptHash(null), "null != valid");
        assertFalse(BCryptExtended.isValidBcryptHash(""), "empty != valid");
        assertFalse(BCryptExtended.isValidBcryptHash("short"), "too short");
    }

    @Test
    @DisplayName("Odrzuca hashe ze złymi wersjami")
    void testIsValidBcryptHashWrongVersion() {
        assertFalse(BCryptExtended.isValidBcryptHash("$3b$12$R9h/cIPz0gi.URNNX3kh2..."),
                "Wrong version");
    }

    // ============================================================================
    // SEKCJA 7: Testy Analiz Hashów
    // ============================================================================

    @Test
    @DisplayName("Parsuje HashInfo z prawidłowego hasha")
    void testGetHashInfoValid() {
        String password = "TestPassword123!";
        String hash = BCryptExtended.hashPasswordSecure(password, 12);

        var info = BCryptExtended.getHashInfo(hash);

        assertNotNull(info, "HashInfo nie powinien być null");
        assertEquals("2b", info.version(), "Version powinny być 2b");
        assertEquals(12, info.rounds(), "Rounds powinny być 12");
        assertNotNull(info.salt(), "Salt nie powinien być null");
    }

    @Test
    @DisplayName("Zwraca null dla invalide hasha")
    void testGetHashInfoInvalid() {
        var info = BCryptExtended.getHashInfo("invalid_hash");

        assertNull(info, "HashInfo powinny być null dla invalide hasha");
    }

    @Test
    @DisplayName("Sprawdza czy hash wymaga rehasha")
    void testShouldRehashOldRounds() {
        String password = "TestPassword";
        String oldHash = BCryptExtended.hashPasswordSecure(password, 10);  // 10 < 12
        String newHash = BCryptExtended.hashPasswordSecure(password, 12);  // 12 = default

        assertTrue(BCryptExtended.shouldRehash(oldHash),
                "Hash z 10 rounds powinien wymaga rehasha");
        assertFalse(BCryptExtended.shouldRehash(newHash),
                "Hash z 12 rounds nie powinien wymaga rehasha");
    }

    @Test
    @DisplayName("Rehaszuje hasło z nowszymi parametrami")
    void testRehashPassword() {
        String password = "MyPassword123!";
        String oldHash = BCryptExtended.hashPasswordSecure(password, 10);

        String newHash = BCryptExtended.rehashPassword(password, oldHash);

        assertNotEquals(oldHash, newHash, "Nowy hash powinny się różnić");
        assertTrue(BCryptExtended.checkpw(password, newHash),
                "Nowy hash powinny verify hasło");

        var newInfo = BCryptExtended.getHashInfo(newHash);
        assertEquals(12, newInfo.rounds(), "Nowy hash powinny mieć 12 rounds");
    }

    @Test
    @DisplayName("Odrzuca rehash z nieprwidłowym hasłem")
    void testRehashPasswordWrongPassword() {
        String correctPassword = "MyPassword123!";
        String wrongPassword = "WrongPassword";
        String oldHash = BCryptExtended.hashPasswordSecure(correctPassword);

        assertThrows(IllegalArgumentException.class, () ->
                        BCryptExtended.rehashPassword(wrongPassword, oldHash),
                "Powinno rzucić dla nieprwidłowego hasła"
        );
    }

    // ============================================================================
    // SEKCJA 8: Testy Constant-Time Compare
    // ============================================================================

    @Test
    @DisplayName("Porównuje identyczne stringi")
    void testConstantTimeCompareEqual() {
        String token = "my_secret_token_1234567890";

        boolean result = BCryptExtended.constantTimeCompare(token, token);

        assertTrue(result, "Identyczne stringi powinny być równe");
    }

    @Test
    @DisplayName("Odrzuca różne stringi")
    void testConstantTimeCompareNotEqual() {
        boolean result = BCryptExtended.constantTimeCompare(
                "token_abc",
                "token_xyz"
        );

        assertFalse(result, "Różne stringi nie powinny być równe");
    }

    @Test
    @DisplayName("Obsługuje null safely")
    void testConstantTimeCompareNull() {
        assertTrue(BCryptExtended.constantTimeCompare(null, null),
                "null == null");
        assertFalse(BCryptExtended.constantTimeCompare(null, "token"),
                "null != token");
        assertFalse(BCryptExtended.constantTimeCompare("token", null),
                "token != null");
    }

    @Test
    @DisplayName("Obsługuje różne długości")
    void testConstantTimeCompareDifferentLength() {
        boolean result = BCryptExtended.constantTimeCompare(
                "short",
                "much_longer_string"
        );

        assertFalse(result, "Różne długości nie powinny być równe");
    }

    // ============================================================================
    // SEKCJA 9: Testy Generowania Haseł
    // ============================================================================

    @Test
    @DisplayName("Generuje hasło prawidłowej długości")
    void testGenerateRandomPasswordLength() {
        for (int len = 8; len <= 20; len++) {
            String password = BCryptExtended.generateRandomPassword(len);
            assertEquals(len, password.length(),
                    "Hasło powinno mieć dokładnie " + len + " znaków");
        }
    }

    @Test
    @DisplayName("Generuje hasło ze wszystkimi typami znaków")
    void testGenerateRandomPasswordContent() {
        String password = BCryptExtended.generateRandomPassword(16);

        boolean hasUpper = password.matches(".*[A-Z].*");
        boolean hasLower = password.matches(".*[a-z].*");
        boolean hasDigit = password.matches(".*\\d.*");
        boolean hasSpecial = password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*");

        assertTrue(hasUpper, "Powinno zawierać wielkie litery");
        assertTrue(hasLower, "Powinno zawierać małe litery");
        assertTrue(hasDigit, "Powinno zawierać cyfry");
        assertTrue(hasSpecial, "Powinno zawierać znaki specjalne");
    }

    @Test
    @DisplayName("Odrzuca invalid długości")
    void testGenerateRandomPasswordInvalidLength() {
        assertThrows(IllegalArgumentException.class, () ->
                        BCryptExtended.generateRandomPassword(7),  // < 8
                "Powinno rzucić dla length < 8"
        );

        assertThrows(IllegalArgumentException.class, () ->
                        BCryptExtended.generateRandomPassword(73),  // > 72
                "Powinno rzucić dla length > 72"
        );
    }

    @Test
    @DisplayName("Generuje różne hasła")
    void testGenerateRandomPasswordUnique() {
        String pwd1 = BCryptExtended.generateRandomPassword(16);
        String pwd2 = BCryptExtended.generateRandomPassword(16);
        String pwd3 = BCryptExtended.generateRandomPassword(16);

        assertNotEquals(pwd1, pwd2, "Hasła powinny się różnić");
        assertNotEquals(pwd2, pwd3, "Hasła powinny się różnić");
    }

    // ============================================================================
    // SEKCJA 10: Testy Integracyjne (End-to-End)
    // ============================================================================

    @Test
    @DisplayName("Full flow: Rejestracja -> Logowanie")
    void testFullAuthenticationFlow() {
        String email = "user@example.com";
        String password = "MySecurePassword123!@";

        // 1. Rejestracja
        String hash = BCryptExtended.hashPasswordSecure(password);
        assertTrue(BCryptExtended.isValidBcryptHash(hash), "Hash powinny być valid");

        // 2. Logowanie
        var result = BCryptExtended.checkPasswordWithDetails(password, hash);
        assertTrue(result.isValid(), "Logowanie powinny się powieść");

        // 3. Zmiana hasła
        String newPassword = "NewSecurePassword456!@";
        String newHash = BCryptExtended.rehashPassword(password, hash);
        var newResult = BCryptExtended.checkPasswordWithDetails(password, newHash);
        assertTrue(newResult.isValid(), "Stare hasło powinno działać z nowym hashem");
    }

    @Test
    @DisplayName("Full flow: Wygaśnięcie -> Zmiana")
    void testPasswordExpiryFlow() {
        long hundredDaysAgo = System.currentTimeMillis() - (100 * 24 * 60 * 60 * 1000L);

        // Hasło wygasło
        assertFalse(BCryptExtended.isPasswordValid(hundredDaysAgo),
                "Stare hasło powinno być wygasłe");

        // Dni do wygaśnięcia = 0
        long days = BCryptExtended.getDaysUntilExpiry(hundredDaysAgo);
        assertEquals(0, days, "Powinno zwrócić 0 dni");

        // Po zmianie hasła - jest ważne
        long now = System.currentTimeMillis();
        assertTrue(BCryptExtended.isPasswordValid(now),
                "Nowe hasło powinno być ważne");
    }
}