import { KeyManagementServiceClient } from "@google-cloud/kms";
import { google } from "@google-cloud/kms/build/protos/protos";
import * as asn1 from "asn1.js";
import BN from "bn.js";
import KeyEncoder from "key-encoder";

export class GcpHsmSigner {

  private EcdsaSigAsnParse: {
    decode: (asnStringBuffer: Buffer, format: "der") => { r: BN; s: BN };
  } = asn1.define("EcdsaSig", function (this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
    this.seq().obj(this.key("r").int(), this.key("s").int());
  });

  private EcdsaPubKey = asn1.define("EcdsaPubKey", function (this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
    this.seq().obj(this.key("algo").seq().obj(this.key("a").objid(), this.key("b").objid()), this.key("pubKey").bitstr());
  });

  private static KEY_ENCODER = new KeyEncoder("secp256k1");

  constructor(private kms: KeyManagementServiceClient, private versionName: string) { }

  public async getPublicKey() {
    const [publicKey] = await this.kms.getPublicKey({
      name: this.versionName,
    });
    if (!publicKey || !publicKey.pem) throw new Error("Can not find public key");

    // GCP KMS returns the public key in pem format,
    // so we need to encode it to der format, and return the hex buffer.
    const der = GcpHsmSigner.KEY_ENCODER.encodePublic(publicKey.pem, "pem", "der");
    const res = this.EcdsaPubKey.decode(Buffer.from(der, "hex"), "der");

    return this.compressPublickey(res.pubKey.data);
  };

  // compressing this according to https://davidederosa.com/basic-blockchain-programming/elliptic-curve-keys
  private compressPublickey(publicKey: Buffer): Uint8Array {
    const pubkey = new Uint8Array(publicKey);
    const compressedPubkey = pubkey.slice(0, 33);

    if (pubkey[64] & 1) {
      compressedPubkey[0] = 3;
    } else {
      compressedPubkey[0] = 2;
    }

    return compressedPubkey;
  }

  public async sign(digest: Buffer): Promise<Buffer> {
    const response = await this.kmsAsymmetricSign(digest);
    if (!response || !response.signature) {
      throw new Error(`GCP KMS call failed`);
    }

    return this.findTerraSignature(response.signature as Buffer);
  }

  private async kmsAsymmetricSign(digest: Buffer): Promise<google.cloud.kms.v1.IAsymmetricSignResponse> {
    const [asymmetricSignResponse] = await this.kms.asymmetricSign({
      name: this.versionName,
      digest: {
        sha256: digest,
      },
    });

    return asymmetricSignResponse;
  }

  private findTerraSignature(signature: Buffer): Buffer {
    const decoded = this.EcdsaSigAsnParse.decode(signature, "der");
    const signatureR = decoded.r;

    const secp256k1N = new BN("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16); // max value on the curve
    const secp256k1halfN = secp256k1N.div(new BN(2)); // half of the curve
    // Because of EIP-2 not all elliptic curve signatures are accepted
    // the value of s needs to be SMALLER than half of the curve
    // i.e. we need to flip s if it's greater than half of the curve
    // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
    const signatureS = decoded.s.gt(secp256k1halfN) ? secp256k1N.sub(decoded.s) : decoded.s;

    return Buffer.concat([signatureR.toBuffer(), signatureS.toBuffer()]);
  }
}
