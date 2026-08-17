BCryptExtended 1.0


    🔒 Advanced BCrypt Implementation


📋 About the Project

BCryptExtended is an extension of the native BCrypt algorithm with advanced features:




    
    
        
            🔐 Hashing
            Secure password hashing with configurable parameters
        
        
            ✅ Validation
            Full password strength validation according to OWASP standards
        
        
            ⏰ Expiration
            Password lifecycle management (90 days)
        
        
            🔄 Rehashing
            Automatic algorithm upgrades in the background
        
        
            🛡️ Timing Attack Protection
            Constant-time comparison for sensitive data
        
        
            📊 Analytics
            Parsing and analysis of hash structures
        
        
            🎲 Generation
            Random secure password generation
        
    




🚀 Quick Start

1. Implementation:



2. User Registration


// Hash password during registration
String plainPassword = "MySecurePassword123!";
String passwordHash = BCryptExtended.hashPasswordSecure(plainPassword);
// Hash: $2b$12$R9h/cIPz0gi.URNNX3kh2...

// Save to database
user.setPasswordHash(passwordHash);
database.save(user);


3. User Login


// Verify password during login
var result = BCryptExtended.checkPasswordWithDetails(
    userInputPassword,
    storedHash
);

if (result.isValid()) {
    authenticateUser();

    // Optional: upgrade password to newer parameters
    if (BCryptExtended.shouldRehash(storedHash)) {
        user.setPasswordHash(
            BCryptExtended.hashPasswordSecure(userInputPassword)
        );
        database.save(user);
    }
}


4. Password Strength Check


PasswordStrength strength = BCryptExtended.checkPasswordStrength(password);
// VERY_WEAK, WEAK, FAIR, GOOD, STRONG, VERY_STRONG

if (strength.score >= PasswordStrength.GOOD.score) {
    // Password is strong enough
    registerUser(password);
}


5. Expiration Management


// Check if password has expired
if (!BCryptExtended.isPasswordValid(user.getLastPasswordChange())) {
    user.setPasswordExpired(true);
    redirectToPasswordChange();
}

// Show warning when few days are left
long daysLeft = BCryptExtended.getDaysUntilExpiry(user.getLastPasswordChange());
if (daysLeft < 7) {
    user.notifyExpiryWarning(daysLeft);
}




📦 File Structure

BCryptExtended/
├── BCryptExtended.java # Main implementation
├── BCryptExtendedExamples.java # Practical examples
├── BCryptExtendedTest.java # Functionality tests
└── README.md # Full documentation
