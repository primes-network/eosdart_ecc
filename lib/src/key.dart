import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/src/utils.dart';
import "package:pointycastle/api.dart" show PrivateKeyParameter;
import 'package:pointycastle/ecc/api.dart'
    show ECPrivateKey, ECSignature, ECPoint;
import "package:pointycastle/signers/ecdsa_signer.dart";
import 'package:pointycastle/macs/hmac.dart';
import "package:pointycastle/digests/sha256.dart";

import './exception.dart';
import './key_base.dart';
import './signature.dart';

/// EOS Public Key
class EOSPublicKey extends EOSKey {
  ECPoint q;

  /// Construct EOS public key from buffer
  EOSPublicKey.fromPoint(this.q);

  /// Construct EOS public key from string
  factory EOSPublicKey.fromString(String keyStr) {
    RegExp publicRegex = RegExp(r"^PUB_([A-Za-z0-9]+)_([A-Za-z0-9]+)",
        caseSensitive: true, multiLine: false);
    Iterable<Match> match = publicRegex.allMatches(keyStr);

    if (match.length == 0) {
      RegExp eosRegex = RegExp(r"^EOS", caseSensitive: true, multiLine: false);
      if (!eosRegex.hasMatch(keyStr)) {
        throw InvalidKey("No leading EOS");
      }
      String publicKeyStr = keyStr.substring(3);
      Uint8List buffer = EOSKey.decodeKey(publicKeyStr);
      return EOSPublicKey.fromBuffer(buffer);
    } else if (match.length == 1) {
      Match m = match.first;
      String keyType = m.group(1);
      Uint8List buffer = EOSKey.decodeKey(m.group(2), keyType);
      return EOSPublicKey.fromBuffer(buffer);
    } else {
      throw InvalidKey('Invalid public key format');
    }
  }

  factory EOSPublicKey.fromBuffer(Uint8List buffer) {
    ECPoint point = EOSKey.secp256k1.curve.decodePoint(buffer);
    return EOSPublicKey.fromPoint(point);
  }

  Uint8List toBuffer() {
    // always compressed
    return q.getEncoded(true);
  }

  String toString() {
    return 'EOS' + EOSKey.encodeKey(this.toBuffer(), keyType);
  }
}

/// EOS Private Key
class EOSPrivateKey extends EOSKey {
  Uint8List d;
  String format;

  /// Constructor EOS private key from the key buffer itself
  EOSPrivateKey.fromBuffer(this.d);

  /// Construct the private key from string
  /// It can come from WIF format for PVT format
  EOSPrivateKey.fromString(String keyStr) {
    RegExp privateRegex = RegExp(r"^PVT_([A-Za-z0-9]+)_([A-Za-z0-9]+)",
        caseSensitive: true, multiLine: false);
    Iterable<Match> match = privateRegex.allMatches(keyStr);

    if (match.length == 0) {
      format = 'WIF';
      keyType = 'K1';
      // WIF
      Uint8List keyWLeadingVersion = EOSKey.decodeKey(keyStr, EOSKey.SHA256X2);
      int version = keyWLeadingVersion.first;
      if (EOSKey.VERSION != version) {
        throw InvalidKey("version mismatch");
      }

      d = keyWLeadingVersion.sublist(1, keyWLeadingVersion.length);
      if (d.lengthInBytes == 33 && d.elementAt(32) == 1) {
        // remove compression flag
        d = d.sublist(0, 32);
      }

      if (d.lengthInBytes != 32) {
        throw InvalidKey('Expecting 32 bytes, got ${d.length}');
      }
    } else if (match.length == 1) {
      format = 'PVT';
      Match m = match.first;
      keyType = m.group(1);
      d = EOSKey.decodeKey(m.group(2), keyType);
    } else {
      throw InvalidKey('Invalid Private Key format');
    }
  }

  /// Generate EOS private key from seed. Please note: This is not random!
  /// For the given seed, the generated key would always be the same
  factory EOSPrivateKey.fromSeed(String seed) {
    Digest s = sha256.convert(utf8.encode(seed));
    return EOSPrivateKey.fromBuffer(s.bytes);
  }

  /// Generate the random EOS private key
  factory EOSPrivateKey.fromRandom() {
    final int randomLimit = 1 << 32;
    Random randomGenerator;
    try {
      randomGenerator = Random.secure();
    } catch (e) {
      randomGenerator = new Random();
    }

    int randomInt1 = randomGenerator.nextInt(randomLimit);
    Uint8List entropy1 = encodeBigInt(BigInt.from(randomInt1));

    int randomInt2 = randomGenerator.nextInt(randomLimit);
    Uint8List entropy2 = encodeBigInt(BigInt.from(randomInt2));

    int randomInt3 = randomGenerator.nextInt(randomLimit);
    Uint8List entropy3 = encodeBigInt(BigInt.from(randomInt3));

    List<int> entropy = entropy1.toList();
    entropy.addAll(entropy2);
    entropy.addAll(entropy3);
    Uint8List randomKey = Uint8List.fromList(entropy);
    Digest d = sha256.convert(randomKey);
    return EOSPrivateKey.fromBuffer(d.bytes);
  }

  /// Check if the private key is WIF format
  bool isWIF() => this.format == 'WIF';

  /// Get the public key string from this private key
  EOSPublicKey toEOSPublicKey() {
    BigInt privateKeyNum = decodeBigInt(this.d);
    ECPoint ecPoint = EOSKey.secp256k1.G * privateKeyNum;

    return EOSPublicKey.fromPoint(ecPoint);
  }

  /// Sign the string data using the private key
  EOSSignature sign(String data) {
    Digest d = sha256.convert(utf8.encode(data));
    return signHash(d.bytes);
  }

  /// Sign the SHA256 hashed data using the private key
  EOSSignature signHash(Uint8List sha256Data) {
    int nonce = 0;

    while (true) {
      ECSignature sig = _deterministicGenerateK(sha256Data, this.d, nonce);
      Uint8List der = EOSSignature.ecSigToDER(sig);

      int lenR = der.elementAt(3);
      int lenS = der.elementAt(5 + lenR);
      if (lenR == 32 && lenS == 32) {
        int i = EOSSignature.calcPubKeyRecoveryParam(
            decodeBigInt(sha256Data), sig, this.toEOSPublicKey());
        i += 4;
        i += 27;
        return EOSSignature(i, sig.r, sig.s);
      }
    }
  }

  String toString() {
    List<int> version = List<int>();
    version.add(EOSKey.VERSION);
    Uint8List keyWLeadingVersion =
        EOSKey.concat(Uint8List.fromList(version), this.d);

    return EOSKey.encodeKey(keyWLeadingVersion, EOSKey.SHA256X2);
  }

  ECSignature _deterministicGenerateK(Uint8List hash, Uint8List x, int nonce) {
    List<int> data = List();
    data.addAll(hash);
    data.add(nonce);

    Uint8List newHash = Uint8List.fromList(data);
    final signer = ECDSASigner(null, HMac(SHA256Digest(), 64));
    var pkp = new PrivateKeyParameter(
        ECPrivateKey(decodeBigInt(x), EOSKey.secp256k1));
    signer.init(true, pkp);
    return signer.generateSignature(newHash);
  }
}
