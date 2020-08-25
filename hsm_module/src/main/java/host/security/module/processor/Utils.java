package host.security.module.processor;

public class Utils {

	public static final String bytesToHexStr(byte[] bArray) {
		String lookup = "0123456789abcdef";
		StringBuffer s = new StringBuffer(bArray.length * 2);

		for (int i = 0; i < bArray.length; i++) {
			s.append(lookup.charAt((bArray[i] >>> 4) & 0x0f));
			s.append(lookup.charAt(bArray[i] & 0x0f));
		}

		return s.toString();
	}

	public static final byte[] hexStrToBytes(String s) {
		byte[] bytes;
		bytes = new byte[s.length() / 2];

		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
		}

		return bytes;
	}
}
