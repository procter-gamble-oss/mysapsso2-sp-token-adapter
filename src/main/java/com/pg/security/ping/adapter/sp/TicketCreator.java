/**
 * Copyright 2017 the Procter & Gamble Company
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *  
 */
package com.pg.security.ping.adapter.sp;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import com.pingidentity.access.KeyAccessor;

/**
 * TicketCreator class creates and signs a byte[] with a pcks#7/CMS signature
 * and then base64 encodes it.
 *
 * @author cdhesse
 *
 */
public class TicketCreator {

	private static final Logger LOG = Logger.getLogger(TicketCreator.class.getName());

	// SHA1/DSA is the only type of signature algorithm SAP currently supports
	private static final String SIGNATURE_ALGO = "SHA1withDSA";

	private static final String PRE_AMBLE = "02";
	private static final String FIELD_ID_SIGNATURE = "FF";
	private static final String LENGTH_4 = "0004";
	private static final String ID_MINS = "07";
	private static final String ID_HOURS = "05";

	private String keystoreAlias;
	private String userId;
	private String sysId;
	private String targetSystemCodepage;
	private String sourceSystemClient;
	private int ticketDurationHours;
	private int ticketDurationMins;

	/**
	 * Constructor
	 *
	 * @param pathToKeystore
	 * @param keystorePass
	 * @param keystoreAlias
	 */
	public TicketCreator(String keystoreAlias, String userId, String sysId, String targetSystemCodePage, String sourceSystemClient,
			int ticketDurationHours, int ticketDurationMins) {
		this.keystoreAlias = keystoreAlias;

		this.targetSystemCodepage = targetSystemCodePage;
		this.userId = userId;
		this.sysId = sysId;
		this.sourceSystemClient = sourceSystemClient;
		this.ticketDurationHours = ticketDurationHours;
		this.ticketDurationMins = ticketDurationMins;
	}
	
	/**
	 * Generate the ticket.
	 *
	 * @param codePage
	 * @param client
	 * @param userId
	 * @param sysId
	 * @param duration
	 * @return
	 */
	public String generateTicket() {

		// Hex data constructed from the parameters
		String hexData = buildDataToSign();

		// The data converted from Hex to byte[]
		byte[] byteDataToSign = toByteArray(hexData);

		String mysapsso2 = null;

		try {
			// The signed data with the signature to be appended at the end
			byte[] signedDataWithSignature = signData(byteDataToSign, keystoreAlias);
			
			// The length of the signed data with signature in Hex
			String lengthOfSignedData = Integer.toHexString(0x10000 | signedDataWithSignature.length).substring(1)
					.toUpperCase();

			// The original byteDataToSign plus the signature header (ID = FF, Length calculated)
			byte[] originalByteDataPlusSignatureHeader = combineByteArrays(byteDataToSign,
					toByteArray(FIELD_ID_SIGNATURE + lengthOfSignedData));
			
			// The cookie as a byte array - originalByteData + the signedByteData
			byte[] mysapsso2ByteArray = combineByteArrays(originalByteDataPlusSignatureHeader, signedDataWithSignature);

			// The cookie encoded with Base64
			byte[] mysapsso2Base64 = Base64.encode(mysapsso2ByteArray);

			// The cookie
			mysapsso2 = new String(mysapsso2Base64);

		} catch (CertificateException | UnrecoverableKeyException | KeyStoreException | OperatorCreationException
				| NoSuchAlgorithmException | CMSException | IOException e) {
			LOG.log(Level.SEVERE, "Exception generating MYSAPSSO2 cookie.", e);
		}

		return mysapsso2;
	}

	/**
	 * Add a ticket String field
	 *
	 * @param index
	 * @param value
	 * @return
	 */
	private String addField(int index, String value) {
		StringBuffer sb = new StringBuffer();
		sb.append("0" + index);
		sb.append(lengthOfHexStringAsHex(value));
		sb.append(value);
		return sb.toString();
	}

	/**
	 * Build the String of data to be signed
	 *
	 * @param userName
	 * @param sysId
	 * @return
	 */
	private String buildDataToSign() {

		// Add header and codepage
		StringBuffer sb = new StringBuffer(PRE_AMBLE + convertStringToHex(this.targetSystemCodepage, false));

		// Add user name INDEX 1
		sb.append(addField(1, convertStringToHex(padRight(this.userId, 12), true)));

		// Add client INDEX 2
		sb.append(addField(2, convertStringToHex(this.sourceSystemClient, true)));

		// Add sysId INDEX 3
		sb.append(addField(3, convertStringToHex(padRight(this.sysId, 8), true)));

		// Add currentTime INDEX 4
		sb.append(addField(4, convertStringToHex(getCurrentTime(), true)));

		// Duration in Hours INDEX 5
		if (ticketDurationHours > 0) {
			sb.append(ID_HOURS);
			sb.append(LENGTH_4);
			sb.append(intToBinaryString(ticketDurationHours));
		}

		// There is no INDEX 6
		
		// Duration in Mins INDEX 7
		if (ticketDurationMins > 0) {
			sb.append(ID_MINS);
			sb.append(LENGTH_4);
			sb.append(intToBinaryString(ticketDurationMins));
			LOG.severe(ticketDurationMins + " mins");
		}

		LOG.severe(sb.toString());
		return sb.toString();
	}

	/**
	 * Append one byte[] to another byte[].
	 *
	 * @param fullBytePayload
	 * @param signedData
	 * @return
	 */
	private byte[] combineByteArrays(byte[] fullBytePayload, byte[] signedData) {
		// create a destination array that is the size of the two arrays
		byte[] mysapsso2ByteArray = new byte[fullBytePayload.length + signedData.length];

		// copy b into start of destination (from pos 0, copy b.length bytes)
		System.arraycopy(fullBytePayload, 0, mysapsso2ByteArray, 0, fullBytePayload.length);

		// copy signature into end of destination (from pos b.length, copy
		// signature.length bytes)
		System.arraycopy(signedData, 0, mysapsso2ByteArray, fullBytePayload.length, signedData.length);

		return mysapsso2ByteArray;
	}

	/**
	 * Convert a string to Hex
	 *
	 * @param str
	 * @param twoByte
	 * @return
	 */
	private String convertStringToHex(String str, boolean twoByte) {

		char[] chars = str.toCharArray();

		StringBuffer hex = new StringBuffer();
		for (int i = 0; i < chars.length; i++) {
			hex.append(Integer.toHexString(chars[i]).toUpperCase());
			if (twoByte) {
				hex.append(Integer.toHexString(0));
				hex.append(Integer.toHexString(0));
			}
		}

		return hex.toString();
	}

	/**
	 * Convert an integer to a binary string of length 8
	 *
	 * @param i
	 * @return
	 */
	private String intToBinaryString(int i) {
		return String.format("%8s", Integer.toHexString(i)).replace(' ', '0');
	}

	/**
	 * Get current time in UTC.
	 *
	 * @return
	 */
	private String getCurrentTime() {
		final Date currentTime = new Date();
		final SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmm");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		return sdf.format(currentTime);
	}

	/**
	 * Calculate length of a Hex String as Hex.
	 *
	 * @param hexValue
	 * @return
	 */
	private String lengthOfHexStringAsHex(String hexValue) {
		return Integer.toHexString(0x10000 | hexValue.length() / 2).substring(1).toUpperCase();
	}

	/**
	 * Pad right with spaces for fixed length cookie values.
	 *
	 * @param s
	 * @param n
	 * @return
	 */
	private String padRight(String s, int n) {
		return String.format("%1$-" + n + "s", s);
	}

	/**
	 * Setup the security provider
	 *
	 * @param keystore
	 * @param keystoreAlias
	 * @param keystorePass
	 * @return
	 * @throws KeyStoreException
	 * @throws CertificateEncodingException
	 * @throws UnrecoverableKeyException
	 * @throws OperatorCreationException
	 * @throws NoSuchAlgorithmException
	 * @throws CMSException
	 */
	private CMSSignedDataGenerator setUpProvider(String keystoreAlias)
			throws KeyStoreException, CertificateEncodingException, UnrecoverableKeyException,
			OperatorCreationException, NoSuchAlgorithmException, CMSException {

		Security.addProvider(new BouncyCastleProvider());

		KeyAccessor ka = new KeyAccessor();

		final List<Certificate> certlist = new ArrayList<>();
		certlist.add(ka.getEncryptionCertificate(keystoreAlias));

		JcaCertStore certstore = new JcaCertStore(certlist);

		ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGO).setProvider("BC")
				.build(ka.getDsigKeypair(keystoreAlias).getPrivateKey());

		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

		generator.addSignerInfoGenerator(
				new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
						.build(signer, ka.getEncryptionCertificate(keystoreAlias)));

		generator.addCertificates(certstore);

		return generator;
	}

	/**
	 * Sign the Data
	 *
	 * @param byteDataToSign
	 * @param pathToKeystore
	 * @param keystorePass
	 * @param keystoreAlias
	 * @return
	 * @throws CMSException
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws UnrecoverableKeyException
	 * @throws OperatorCreationException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	private byte[] signData(byte[] byteDataToSign, String keystoreAlias)
			throws CMSException, IOException, KeyStoreException, UnrecoverableKeyException, OperatorCreationException,
			NoSuchAlgorithmException, CertificateException {
		CMSSignedDataGenerator signatureGenerator = setUpProvider(keystoreAlias);

		return signPkcs7(byteDataToSign, signatureGenerator);
	}

	/**
	 * Sign the content
	 *
	 * @param content
	 * @param generator
	 * @return
	 * @throws CMSException
	 * @throws IOException
	 */
	private byte[] signPkcs7(final byte[] content, final CMSSignedDataGenerator generator)
			throws CMSException, IOException {

		CMSTypedData cmsdata = new CMSProcessableByteArray(content);
		CMSSignedData signeddata = generator.generate(cmsdata, true);

		return signeddata.getEncoded();
	}

	/**
	 * Convert a String to a byte[]
	 *
	 * @param s
	 * @return
	 */
	private byte[] toByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}
}