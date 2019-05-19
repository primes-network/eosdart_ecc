import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import "package:pointycastle/api.dart" show PublicKeyParameter;
import 'package:pointycastle/ecc/api.dart'
    show ECPublicKey, ECSignature, ECPoint;
import "package:pointycastle/signers/ecdsa_signer.dart";
import 'package:pointycastle/macs/hmac.dart';
import "package:pointycastle/digests/sha256.dart";
import 'package:pointycastle/src/utils.dart';

import './exception.dart';
import './key.dart';
import './key_base.dart';

/// EOS Signature
class EOSSignature extends EOSKey {
  int i;
  ECSignature ecSig;

  /// Default constructor from i, r, s
  EOSSignature(this.i, BigInt r, BigInt s) {
    this.keyType = 'K1';
    this.ecSig = ECSignature(r, s);
  }

  /// Construct EOS signature from buffer
  EOSSignature.fromBuffer(Uint8List buffer, String keyType) {
    this.keyType = keyType;

    if (buffer.lengthInBytes != 65) {
      throw InvalidKey(
          'Invalid signature length, got: ${buffer.lengthInBytes}');
    }

    i = buffer.first;

    if (i - 27 != i - 27 & 7) {
      throw InvalidKey('Invalid signature parameter');
    }

    BigInt r = decodeBigInt(buffer.sublist(1, 33));
    BigInt s = decodeBigInt(buffer.sublist(33, 65));
    this.ecSig = ECSignature(r, s);
  }

  /// Construct EOS signature from string
  factory EOSSignature.fromString(String signatureStr) {
    RegExp sigRegex = RegExp(r"^SIG_([A-Za-z0-9]+)_([A-Za-z0-9]+)",
        caseSensitive: true, multiLine: false);
    Iterable<Match> match = sigRegex.allMatches(signatureStr);

    if (match.length == 1) {
      Match m = match.first;
      String keyType = m.group(1);
      Uint8List key = EOSKey.decodeKey(m.group(2), keyType);
      return EOSSignature.fromBuffer(key, keyType);
    }

    throw InvalidKey("Invalid EOS signature");
  }

  /// Verify the signature of the string data
  bool verify(String data, EOSPublicKey publicKey) {
    Digest d = sha256.convert(utf8.encode(data));

    return verifyHash(d.bytes, publicKey);
  }

  /// Verify the signature from in SHA256 hashed data
  bool verifyHash(Uint8List sha256Data, EOSPublicKey publicKey) {
    ECPoint q = publicKey.q;
    final signer = ECDSASigner(null, HMac(SHA256Digest(), 64));
    signer.init(false, PublicKeyParameter(ECPublicKey(q, EOSKey.secp256k1)));

    return signer.verifySignature(sha256Data, this.ecSig);
  }

  String toString() {
    List<int> b = List();
    b.add(i);
    b.addAll(encodeBigInt(this.ecSig.r));
    b.addAll(encodeBigInt(this.ecSig.s));

    Uint8List buffer = Uint8List.fromList(b);
    return 'SIG_${keyType}_${EOSKey.encodeKey(buffer, keyType)}';
  }

  /// ECSignature to DER format bytes
  static Uint8List ecSigToDER(ECSignature ecSig) {
    List<int> r = EOSKey.toSigned(encodeBigInt(ecSig.r));
    List<int> s = EOSKey.toSigned(encodeBigInt(ecSig.s));

    List<int> b = List();
    b.add(0x02);
    b.add(r.length);
    b.addAll(r);

    b.add(0x02);
    b.add(s.length);
    b.addAll(s);

    b.insert(0, b.length);
    b.insert(0, 0x30);

    return Uint8List.fromList(b);
  }

  /// Find the public key recovery factor
  static int calcPubKeyRecoveryParam(
      BigInt e, ECSignature ecSig, EOSPublicKey publicKey) {
    for (int i = 0; i < 4; i++) {
      ECPoint Qprime = recoverPubKey(e, ecSig, i);
      if (Qprime == publicKey.q) {
        return i;
      }
    }
    throw 'Unable to find valid recovery factor';
  }

  /// Recovery EOS public key from ECSignature
  static ECPoint recoverPubKey(BigInt e, ECSignature ecSig, int i) {
    BigInt n = EOSKey.secp256k1.n;
    ECPoint G = EOSKey.secp256k1.G;

    BigInt r = ecSig.r;
    BigInt s = ecSig.s;

    // A set LSB signifies that the y-coordinate is odd
    int isYOdd = i & 1;

    // The more significant bit specifies whether we should use the
    // first or second candidate key.
    int isSecondKey = i >> 1;

    // 1.1 Let x = r + jn
    BigInt x = isSecondKey > 0 ? r + n : r;
    ECPoint R = EOSKey.secp256k1.curve.decompressPoint(isYOdd, x);
    ECPoint nR = R * n;
    if (!nR.isInfinity) {
      throw 'nR is not a valid curve point';
    }

    BigInt eNeg = (-e) % n;
    BigInt rInv = r.modInverse(n);

    ECPoint Q = multiplyTwo(R, s, G, eNeg) * rInv;
    return Q;
  }

  static bool testBit(BigInt j, int n) {
    return (j >> n).toUnsigned(1).toInt() == 1;
  }

  static ECPoint multiplyTwo(ECPoint t, BigInt j, ECPoint x, BigInt k) {
    int i = max(j.bitLength, k.bitLength) - 1;
    ECPoint R = t.curve.infinity;
    ECPoint both = t + x;

    while (i >= 0) {
      bool jBit = testBit(j, i);
      bool kBit = testBit(k, i);

      R = R.twice();

      if (jBit) {
        if (kBit) {
          R = R + both;
        } else {
          R = R + t;
        }
      } else if (kBit) {
        R = R + x;
      }

      --i;
    }

    return R;
  }
}
