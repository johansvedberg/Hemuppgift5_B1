package main;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Main {

	public static void main(String[] args) throws NoSuchAlgorithmException {

		String publicIdentity = "walterwhite@crypto.sec";
		BigInteger p = new BigInteger("9240633d434a8b71a013b5b00513323f", 16);
		BigInteger q = new BigInteger("f870cfcd47e6d5a0598fc1eb7e999d1b", 16);
		ArrayList<BigInteger> message = new ArrayList<BigInteger>();

		message.add(new BigInteger("2f2aa07cfb07c64be95586cfc394ebf26c2f383f90ce1d494dde9b2a3728ae9b", 16));
		message.add(new BigInteger("63ed324439c0f6b823d4828982a1bbe5c34e66d985f55792028acd2e207daa4f", 16));
		message.add(new BigInteger("85bb7964196bf6cce070a5e8f30bc822018a7ad70690b97814374c54fddf8e4b", 16));
		message.add(new BigInteger("30fbcc37643cc433d42581f784e3a0648c91c9f46b5671b71f8cc65d2737da5c", 16));
		message.add(new BigInteger("5a732f73fb288d2c90f537a831c18250af720071b6a7fac88a5de32b0df67c53", 16));
		message.add(new BigInteger("504d6be8542e546dfbd78a7ac470fab7f35ea98f2aff42c890f6146ae4fe11d6", 16));
		message.add(new BigInteger("10956aff2a90c54001e85be12cb2fa07c0029c608a51c4c804300b70a47c33bf", 16));
		message.add(new BigInteger("461aa66ef153649d69b9e2c699418a7f8f75af3f3172dbc175311d57aeb0fd12", 16));

		IBE ibe = new IBE(publicIdentity, p, q, message);

	}

}
