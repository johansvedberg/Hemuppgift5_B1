package main;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.xml.bind.DatatypeConverter;

public class IBE {
	private BigInteger ZERO = BigInteger.valueOf(0);
	private BigInteger ONE = BigInteger.valueOf(1);
	private BigInteger TWO = BigInteger.valueOf(2);
	private BigInteger THREE = BigInteger.valueOf(3);
	private BigInteger FOUR = BigInteger.valueOf(4);
	private BigInteger FIVE = BigInteger.valueOf(5);
	private BigInteger SEVEN = BigInteger.valueOf(7);
	private BigInteger EIGHT = BigInteger.valueOf(8);

	public IBE(String publicIdentity, BigInteger p, BigInteger q, ArrayList<BigInteger> message)
			throws NoSuchAlgorithmException {

		byte[] identityBytes = publicIdentity.getBytes();

		BigInteger m = p.multiply(q);

		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		digest.update(identityBytes);
		byte[] digestBytes = digest.digest();

		BigInteger a = new BigInteger(toHex(digestBytes), 16);

		while (jacobi(a, m) != 1) {

			digest.update(digestBytes);
			digestBytes = digest.digest();
			a = new BigInteger(toHex(digestBytes), 16);

		}

		String identityValue = a.toString(16);
		System.out.println("Identity: " + identityValue);

		BigInteger exponent = m.add(FIVE).subtract(p).subtract(q).divide(EIGHT);

		BigInteger r = a.modPow(exponent, m);

		System.out.println("Private key: " + r.toString(16));

		String value = "";

		for (BigInteger b : message) {

			BigInteger s = b.add(r.multiply(TWO));

			int c = jacobi(s, m);

			if (c == -1) {
				c = 0;
			}

			value = value + Integer.toBinaryString(c);

		}

		System.out.println("Decoded: " + Integer.parseInt(value, 2));

	}

	private int jacobi(BigInteger a, BigInteger m) {

		int jacobi = 0;

		if (ZERO.equals(a)) {
			jacobi = (ONE.equals(m)) ? 1 : 0;
		} else if (TWO.equals(a)) {
			BigInteger mod = m.mod(EIGHT);
			if (ONE.equals(mod) || SEVEN.equals(mod)) {
				jacobi = 1;
			} else if (THREE.equals(mod) || FIVE.equals(mod))
				jacobi = -1;
		} else if (a.compareTo(m) >= 0) {
			jacobi = jacobi(a.mod(m), m);
		} else if (ZERO.equals(a.mod(TWO))) {
			jacobi = jacobi(TWO, m) * jacobi(a.divide(TWO), m);
		} else {
			jacobi = (THREE.equals(a.mod(FOUR)) && THREE.equals(m.mod(FOUR))) ? -jacobi(m, a) : jacobi(m, a);
		}

		return jacobi;

	}

	private String toHex(byte[] array) {
		return DatatypeConverter.printHexBinary(array);
	}

}
