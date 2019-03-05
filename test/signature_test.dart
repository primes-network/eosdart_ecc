import 'package:eosdart_ecc/eosdart_ecc.dart';
import 'package:test/test.dart';

void main() {
  group('EOS signature tests', () {
    test('Construct EOS signature from string', () {
      String sigStr =
          'SIG_K1_Kg417TSLuhzSpU2bGa21kD1UNaTfAZSCcKmKpZ6fnx3Nqu22gzG3ND4Twur7bzX8oS1J91JvV4rMJcFycGqFBSaY2SJcEQ';
      EOSSignature signature = EOSSignature.fromString(sigStr);
      print(signature);

      expect(sigStr, signature.toString());
    });
  });
}
