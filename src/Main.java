import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Main {

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		String p = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
		String g = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
		BigInteger bigIntp = toDec(p);
		BigInteger bigIntg = toDec(g);
		// BigInteger a = new BigInteger(bigIntp.bitLength()-1, 1 ,new Random());
		BigInteger a = new BigInteger(
				"48234616218401805821789514296955096952036972671222747494110332355655895065623273182684882276122212881717093076089169238329348946772214072859752497394671617410495311374397594921066411189357565653626770894645869917725182879582869848692275821343462600013317296292258657390074241073219506327510382743279538376459");

		BigInteger A = calcKey(a, bigIntg, bigIntp);

		String AinHex = A.toString(16);
		FileWriter out = new FileWriter("A", false);
		out.write(AinHex);
		out.close();

		String Vhex = "08E5678E931AC6EF0D6BAD8F0B608E997DDC9C83B883A5AA7CA1223DF2ECAE51D23391CEBD5A525E6F4819B0D71F96AC647F6E30E03DB2589B94FFB9F2065A5CD78ACFAFE4D3F2375C1485E39F5B6D9677D4B9E236F073F96184F8122E3A7C412BA2278480DBFB5077A3DB9B1A1F82C5A621C42387AE170CB11E7B519C5BCC41";
		BigInteger bigIntV = toDec(Vhex);
		BigInteger V = calcKey(a, bigIntV, bigIntp);
		String hash = calculaHash(V);
		String S = hash.substring(0, 16);
		
		String texthex = "ola";//decifraTexto("AES/CBC/PKCS5Padding", String textoCifrado, S);
		System.out.println(new StringBuilder(texthex).reverse().toString());
		
	}

	public static BigInteger toDec(String hex) {
		BigInteger dec = new BigInteger(hex, 16);
		return dec;
	}

	public static BigInteger calcKey(BigInteger a, BigInteger g, BigInteger p) {
		BigInteger A = g.modPow(a, p);
		return A;
	}

	public static String calculaHash(BigInteger V) throws NoSuchAlgorithmException {
		byte[] hash = null;

		String val = V.toString();
		System.out.println(val);
		MessageDigest md = MessageDigest.getInstance("SHA-256");

		hash = md.digest(val.getBytes());

		System.out.println(toHexString(hash));

		return toHexString(hash);

	}

	public static String toHexString(byte[] array) {
		return javax.xml.bind.DatatypeConverter.printHexBinary(array).toLowerCase();
	}

	public static String decifraTexto(String operacao, String textoCifrado, String chave) throws Exception {
		Cipher cipher = Cipher.getInstance(operacao);

		// pega o IV do texto de input
		IvParameterSpec ivSpec = pegaIV(textoCifrado);

		// passa chave para array de bytes
		byte[] bytes = toByteArray(chave);
		SecretKeySpec skeySpec = new SecretKeySpec(bytes, "AES");

		// Decifra o texto de input usando iv e chave
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
		byte[] bytesDecifrado = cipher.doFinal(pegaTextoCifrado(textoCifrado));

		String textoDecifrado = new String(bytesDecifrado);
		return textoDecifrado;
	}
	
	 public static String cifraTexto(String operacao, String texto, String chave) throws Exception{
	        Cipher cipher = Cipher.getInstance(operacao);
	        //Gera IV randomico
	        IvParameterSpec ivSpec = geraIVrandomico();

	        //Passa para String em hexa
	        String iv = toHexString(ivSpec.getIV());

	        //Secret key
	        SecretKeySpec keySpec = new SecretKeySpec(toByteArray(chave), "AES");

	        //cifra texto com chave e iv randomico
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
	        byte[] bytes = cipher.doFinal(texto.getBytes());

	        //Passa para String
	        String textoCifrado = String.join("", iv, toHexString(bytes));

	        return textoCifrado;
	    }
	 
	 public static IvParameterSpec geraIVrandomico(){
	        byte[] iv = new byte[16];
	        SecureRandom r = new SecureRandom();
	        r.nextBytes(iv);
	        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

	        return ivParameterSpec;
	    }

	public static IvParameterSpec pegaIV(String textoCifrado) {
		String iv = textoCifrado.substring(0, 16);

		byte[] bytes = toByteArray(iv);

		return new IvParameterSpec(bytes);
	}

	public static byte[] toByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	public static byte[] pegaTextoCifrado(String cipher_text) {
		String encrypted_part = cipher_text.substring(16);
		return toByteArray(encrypted_part);
	}

}
