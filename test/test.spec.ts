import { expect } from 'chai';
import { randomBytes } from 'crypto';
import { GcpHsmSigner } from '../src/GcpHsmSigner';
import { MnemonicKey } from '@terra-money/terra.js';
import { GcpHsmKey } from '../src/GcpHsmKey';
import { SHA256, Word32Array } from 'jscrypto';
import { KeyManagementServiceClient } from "@google-cloud/kms";

import * as secret from '../.secret.json';

const kms = new KeyManagementServiceClient();
const versionName = kms.cryptoKeyVersionPath(
  secret.gcpInfo.projectId,
  secret.gcpInfo.locationId,
  secret.gcpInfo.keyRingId,
  secret.gcpInfo.keyId,
  secret.gcpInfo.versionId
);

function equalBuffer(buf1: Uint8Array, buf2: Uint8Array) {
  if (buf1.byteLength != buf2.byteLength) return false;
  var dv1 = new Int8Array(buf1);
  var dv2 = new Int8Array(buf2);
  for (var i = 0; i != buf1.byteLength; i++) {
    if (dv1[i] != dv2[i]) return false;
  }
  return true;
}

describe('test', () => {
  it('Public key should always be the same.', async () => {
    const utils1 = new GcpHsmSigner(kms, versionName);
    const utils2 = new GcpHsmSigner(kms, versionName);

    const pubKey1 = await utils1.getPublicKey();
    const pubKey2 = await utils2.getPublicKey();
    expect(equalBuffer(pubKey1, pubKey2)).to.be.true;
  });


  it('public key length test', async () => {
    const utils = new GcpHsmSigner(kms, versionName);
    const secp256k1 = require('secp256k1');
    const privateKey = randomBytes(32);

    // Rawkey
    const publicKey = secp256k1.publicKeyCreate(
      new Uint8Array(privateKey),
      true
    );

    // GCP HSM
    const hsmPublicKey = await utils.getPublicKey();

    expect(publicKey.length).to.equal(hsmPublicKey.length);
  });


  it('signature verify test', async () => {
    const utils = new GcpHsmSigner(kms, versionName);
    const secp256k1 = require('secp256k1');

    const testMessage = Buffer.from("test message");

    // Mnemonic key
    const mnemonicKey = new MnemonicKey({
      mnemonic: 'notice oak worry limit wrap speak medal online prefer cluster roof addict wrist behave treat actual wasp year salad speed social layer crew genius'
    })
    const mnemonicSignature = await mnemonicKey.sign(testMessage);
    const mnemonicPublicKey = secp256k1.publicKeyCreate(
      new Uint8Array(mnemonicKey.privateKey),
      true
    );

    // GCP HSM
    const hsmPublicKey = await utils.getPublicKey();
    const gcpHsmKey = new GcpHsmKey(utils, hsmPublicKey);
    const hsmSignature = await gcpHsmKey.sign(testMessage);

    const hash = Buffer.from(
      SHA256.hash(new Word32Array(testMessage)).toString(),
      'hex'
    );

    expect(secp256k1.ecdsaVerify(hsmSignature, hash, hsmPublicKey)).is.be.true;
    expect(secp256k1.ecdsaVerify(mnemonicSignature, hash, mnemonicPublicKey)).is.be.true;
  });
});

