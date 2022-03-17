import { LCDClient, Key, MnemonicKey, MsgSend } from '@terra-money/terra.js';
import { KeyManagementServiceClient } from "@google-cloud/kms";
import { GcpHsmKey } from './GcpHsmKey';
import { GcpHsmSigner } from './GcpHsmSigner';

import * as secret from './.secret.json';

const terra = new LCDClient({
	URL: 'https://bombay-lcd.terra.dev',
	chainID: 'bombay-12'
});

const sendLuna = async () => {
	const mnemonicKey = new MnemonicKey({
		mnemonic: secret.mnemonic
	})

	// GCP HSM
	const kms = new KeyManagementServiceClient();
	const versionName = kms.cryptoKeyVersionPath(
		secret.gcpInfo.projectId,
		secret.gcpInfo.locationId,
		secret.gcpInfo.keyRingId,
		secret.gcpInfo.keyId,
		secret.gcpInfo.versionId
	);
	const gcpHsmUtils = new GcpHsmSigner(kms, versionName);
	const pubkey = await gcpHsmUtils.getPublicKey();
	const gcpHsmKey: Key = new GcpHsmKey(gcpHsmUtils, pubkey);

	console.log(mnemonicKey.publicKey)
	console.log(gcpHsmKey.publicKey);

	const mnemonicWallet = terra.wallet(mnemonicKey);
	const gcpHsmWallet = terra.wallet(gcpHsmKey);

	console.log("mnemonic wallet addr = ", mnemonicWallet.key.accAddress);
	console.log("GCP HSM wallet addr = ", gcpHsmWallet.key.accAddress);

	const send = new MsgSend(
		gcpHsmWallet.key.accAddress,
		mnemonicWallet.key.accAddress,
		"1uluna"
	);

	try {
		const tx = await gcpHsmWallet.createAndSignTx({
			msgs: [send],
			memo: 'gcp hsm send test',
		})

		const result = await terra.tx.broadcast(tx);

		console.log("+++ result: ", result);
	} catch (err) {
		console.log("+++ error: ", err);
	}
}

sendLuna();