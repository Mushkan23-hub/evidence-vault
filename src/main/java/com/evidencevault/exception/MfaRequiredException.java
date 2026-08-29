package com.evidencevault.exception;

/** Thrown mid-login when the password was correct but the account has TOTP MFA enabled and no
 *  (or an incorrect) code was supplied yet. Mapped to HTTP 401 with a distinguishable error code
 *  so the frontend can show a "enter your authenticator code" step instead of a generic failure. */
public class MfaRequiredException extends RuntimeException {
    public MfaRequiredException(String message) {
        super(message);
    }
}
