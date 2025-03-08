// decode Token string into claims
import 'dart:convert';

import 'b64url_rfc7515.dart';
import 'claim.dart';
import 'constant_time_compare.dart';
import 'exception.dart';
import 'package:crypto/crypto.dart';

/// Header checking function type used by [decodeAndVerifyHS256].
typedef JOSEHeaderCheck = bool Function(Map<String, dynamic> joseHeader);

/// Default JOSE Header checker.
///
/// Returns true (header is ok) if the 'typ' Header Parameter is absent, or it
/// is present with the exact value of 'JWT'. Otherwise, false (header is
/// rejected).
///
/// This implementation allows [decodeAndVerifyHS256] to exactly replicate
/// its previous behaviour.
///.
/// Note: this check is more restrictive than what RFC 7519 requires, since the
/// value of 'JWT' is only a recommendation and it is supposed to be case
/// insensitive. See <https://tools.ietf.org/html/rfc7519#section-5.1>
bool defaultJWTHeaderCheck(Map<String, dynamic> h) {
  if (!h.containsKey('typ')) {
    return true;
  }

  final dynamic typ = h['typ'];
  return typ == 'JWT';
}

/// Extracts the claim set from a JWT.
///
/// Throws a [JwtException] if the JWT is invalid.
///
///     final decClaimSet = decodeToken(token);
///     print(decClaimSet);
JwtClaim decodeToken(String token) {
  try {
    final parts = token.split('.');
    if (parts.length != 3) {
      throw JwtException.invalidToken;
    }

    // // Decode header and payload
    // final headerString = B64urlEncRfc7515.decodeUtf8(parts[0]);
    // // Check header
    // final dynamic header = json.decode(headerString);
    // if (header is Map) {
    //   // Perform any custom checks on the header
    //   if (headerCheck != null && !headerCheck(header.cast<String, dynamic>())) {
    //     throw JwtException.invalidToken;
    //   }

    //   // if (header['alg'] != 'HS256') {
    //   //   throw JwtException.hashMismatch;
    //   // }
    // } else {
    //   throw JwtException.headerNotJson;
    // }

    // // Verify signature: calculate signature and compare to token's signature
    // final data = '${parts[0]}.${parts[1]}';
    // final calcSig = hmac.convert(data.codeUnits).bytes;
    // final tokenSig = B64urlEncRfc7515.decode(parts[2]);
    // // Signature does not match calculated
    // if (!secureCompareIntList(calcSig, tokenSig))
    //   throw JwtException.hashMismatch;

    // Convert payload into a claim set
    final payloadString = B64urlEncRfc7515.decodeUtf8(parts[1]);
    final dynamic payload = json.decode(payloadString);
    if (payload is Map) {
      return JwtClaim.fromMap(payload);
    } else {
      throw JwtException.payloadNotJson; // is JSON, but not a JSON object
    }
  } on FormatException {
    // Can be caused by:
    //   - header or payload parts are not Base64url Encoding
    //   - bytes in the header or payload are not proper UTF-8
    //   - string in header or payload cannot be parsed into JSON
    throw JwtException.invalidToken;
  }
}

/// Verifies the signature and extracts the claim set from a JWT.
///
/// The signature is verified using the [hmacKey] with the HMAC SHA-256
/// algorithm.
///
/// The [headerCheck] is an optional function to check the header.
/// It defaults to [defaultJWTHeaderCheck].
///
/// Throws a [JwtException] if the signature does not verify or the
/// JWT is invalid.
///
///     final decClaimSet = decodeAndVerifyHS256(token, key);
///     print(decClaimSet);
JwtClaim decodeAndVerifyHS256(
  String token,
  String hmacKey, {
  JOSEHeaderCheck? headerCheck = defaultJWTHeaderCheck,
}) {
  try {
    final hmac = Hmac(sha256, hmacKey.codeUnits);

    final parts = token.split('.');
    if (parts.length != 3) {
      throw JwtException.invalidToken;
    }

    // Decode header and payload
    final headerString = B64urlEncRfc7515.decodeUtf8(parts[0]);
    // Check header
    final dynamic header = json.decode(headerString);
    if (header is Map) {
      // Perform any custom checks on the header
      if (headerCheck != null &&
          !headerCheck(header.cast<String, dynamic?>())) {
        throw JwtException.invalidToken;
      }

      if (header['alg'] != 'HS256') {
        throw JwtException.hashMismatch;
      }
    } else {
      throw JwtException.headerNotJson;
    }

    // Verify signature: calculate signature and compare to token's signature
    final data = '${parts[0]}.${parts[1]}';
    final calcSig = hmac.convert(data.codeUnits).bytes;
    final tokenSig = B64urlEncRfc7515.decode(parts[2]);
    // Signature does not match calculated
    if (!constantTimeCompareList(calcSig, tokenSig)) {
      throw JwtException.hashMismatch;
    }

    // Convert payload into a claim set
    final payloadString = B64urlEncRfc7515.decodeUtf8(parts[1]);
    final dynamic payload = json.decode(payloadString);
    if (payload is Map) {
      return JwtClaim.fromMap(payload);
    } else {
      throw JwtException.payloadNotJson; // is JSON, but not a JSON object
    }
  } on FormatException {
    // Can be caused by:
    //   - header or payload parts are not Base64url Encoding
    //   - bytes in the header or payload are not proper UTF-8
    //   - string in header or payload cannot be parsed into JSON
    throw JwtException.invalidToken;
  }
}
