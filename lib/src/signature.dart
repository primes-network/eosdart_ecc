import 'dart:typed_data';

import './exception.dart';
import './key_base.dart';

class EOSSignature extends EOSKey {
  int i;
  Uint8List r;
  Uint8List s;
  Uint8List buffer;

  /// Default constructor from the key buffer itself
  EOSSignature(Uint8List buffer, String keyType) {
    this.keyType = keyType;
    this.buffer = buffer;

    if (buffer.length != 65) {
      throw InvalidKey('Invalid signature length');
    }

    i = buffer.first;

    if (i - 27 != i - 27 & 7) {
      throw InvalidKey('Invalid signature parameter');
    }

    r = buffer.sublist(1, 33);
    s = buffer.sublist(33, 65);
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
      return EOSSignature(key, keyType);
    }

    throw InvalidKey("Invalid EOS signature");
  }

  String toString() {
    return 'SIG_${keyType}_${EOSKey.encodeKey(buffer, keyType)}';
  }
}
