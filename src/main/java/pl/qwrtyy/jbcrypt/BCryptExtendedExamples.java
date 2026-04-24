package pl.qwrtyy.jbcrypt;

/**
 * Przykłady użycia BCryptExtended w realnych scenariuszach.
 *
 * <p>Pokazuje:</p>
 * <ul>
 *     <li>Rejestrację użytkownika</li>
 *     <li>Logowanie</li>
 *     <li>Rehashing hasła</li>
 *     <li>Walidację siły hasła</li>
 *     <li>Obsługę błędów</li>
 * </ul>
 *
 * @author qwrtyy
 * @since 2.1
 */
@SuppressWarnings("unused")
public final class BCryptExtendedExamples {

    private BCryptExtendedExamples() {
        // utility class
    }

    // ============================================================================
    // SCENARIUSZ 1 - REJESTRACJA UŻYTKOWNIKA
    // ============================================================================

    public static String registerUser(String password) {
        // 1. Sprawdzenie siły hasła
        var strength = BCryptExtended.checkPasswordStrength(password);

        if (strength.score < 3) {
            throw new IllegalArgumentException(
                    "Hasło jest za słabe: " + strength.description
            );
        }

        // 2. Hashowanie
        String hash = BCryptExtended.hashPasswordSecure(password);

        // 3. Zapis do bazy (symulacja)
        System.out.println("[REGISTER]");
        System.out.println("Hash zapisany do DB: " + hash);

        return hash;
    }

    // ============================================================================
    // SCENARIUSZ 2 - LOGOWANIE UŻYTKOWNIKA
    // ============================================================================

    public static boolean loginUser(String inputPassword, String storedHash) {
        var result = BCryptExtended.checkPasswordWithDetails(inputPassword, storedHash);

        if (!result.isValid()) {
            System.out.println("[LOGIN] Błąd: " + result.error());
            return false;
        }

        System.out.println("[LOGIN] Sukces");

        // Sprawdzenie czy trzeba rehashować
        if (BCryptExtended.shouldRehash(storedHash)) {
            System.out.println("[LOGIN] Hash przestarzały -> rehash");

            String newHash = BCryptExtended.rehashPassword(inputPassword, storedHash);

            // symulacja zapisu
            System.out.println("[LOGIN] Nowy hash zapisany: " + newHash);
        }

        return true;
    }

    // ============================================================================
    // SCENARIUSZ 3 - ZMIANA HASŁA
    // ============================================================================

    public static String changePassword(String oldPassword, String newPassword, String storedHash) {
        // 1. Weryfikacja starego hasła
        if (!BCryptExtended.checkpw(oldPassword, storedHash)) {
            throw new IllegalArgumentException("Stare hasło niepoprawne");
        }

        // 2. Walidacja nowego
        BCryptExtended.validatePassword(newPassword);

        var strength = BCryptExtended.checkPasswordStrength(newPassword);
        if (strength.score < 3) {
            throw new IllegalArgumentException("Nowe hasło za słabe: " + strength.description);
        }

        // 3. Hashowanie
        String newHash = BCryptExtended.hashPasswordSecure(newPassword);

        System.out.println("[CHANGE PASSWORD] Sukces");

        return newHash;
    }

    // ============================================================================
    // SCENARIUSZ 4 - RESET HASŁA (GENEROWANIE)
    // ============================================================================

    public static String resetPassword() {
        String newPassword = BCryptExtended.generateRandomPassword(16);
        String hash = BCryptExtended.hashPasswordSecure(newPassword);

        System.out.println("[RESET PASSWORD]");
        System.out.println("Nowe hasło: " + newPassword);
        System.out.println("Hash: " + hash);

        return hash;
    }

    // ============================================================================
    // SCENARIUSZ 5 - WALIDACJA HASHA Z BAZY
    // ============================================================================

    public static void validateHash(String hash) {
        System.out.println("[HASH VALIDATION]");

        if (!BCryptExtended.isValidBcryptHash(hash)) {
            System.out.println("Niepoprawny format hash");
            return;
        }

        var info = BCryptExtended.getHashInfo(hash);

        if (info != null) {
            System.out.println("Wersja: " + info.version());
            System.out.println("Rounds: " + info.rounds());
            System.out.println("Salt: " + info.salt());
        }
    }

    // ============================================================================
    // SCENARIUSZ 6 - TOKEN COMPARISON (SECURITY)
    // ============================================================================

    public static boolean compareTokens(String tokenA, String tokenB) {
        boolean result = BCryptExtended.constantTimeCompare(tokenA, tokenB);

        System.out.println("[TOKEN COMPARE] " + (result ? "MATCH" : "NO MATCH"));

        return result;
    }

    // ============================================================================
    // MAIN - SZYBKIE TESTY
    // ============================================================================

    public static void main(String[] args) {
        System.out.println("=== BCryptExtendedExamples ===");

        String password = "MySecurePassword123!";

        // Rejestracja
        String hash = registerUser(password);

        // Logowanie
        loginUser(password, hash);

        // Zmiana hasła
        hash = changePassword(password, "NewSecurePassword456!", hash);

        // Reset
        resetPassword();

        // Walidacja
        validateHash(hash);

        // Token compare
        compareTokens("abc123", "abc123");
    }
}