export const validateUsername = (username) => {
    // Alphanumeric, underscores, and dots. 3-20 characters.
    const usernameRegex = /^[a-zA-Z0-9._]{3,20}$/;
    return usernameRegex.test(username);
};

export const validatePassword = (password) => {
    // Min 8 characters, at least one uppercase letter, one lowercase letter, one number and one special character
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
};
