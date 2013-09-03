package us.walkenhorst.crypto;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Set;
/*
The MIT License (MIT)

Copyright (c) 2013 Jacob Walkenhorst

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
public class PasswordMessageDigest extends PasswordDigest{
	
	public enum MessageDigestAlgorithm{
		MD2("MD2"), MD5("MD5"), SHA1("SHA"), SHA256("SHA-256"), SHA384("SHA-384"), SHA512("SHA-512");
		
		public final String algorithm;
		
		public static boolean isSupported(String algorithm){
			Set<String> algorithms = Security.getAlgorithms("MessageDigest");
			return algorithms.contains(algorithm);
		}
		
		public boolean isSupported(){
			return isSupported(this.algorithm);
		}
		
		private MessageDigestAlgorithm(String algorithm){
			this.algorithm = algorithm;
		}
		
		public static void main(String[] args){
			int count = 0;
			for (MessageDigestAlgorithm digest : MessageDigestAlgorithm.values()){
				if (!digest.isSupported()){
					count++;
					System.err.println("Missing algorithm:" + digest);
				}
			}
			if (count == 0) System.out.println("All digest algorithms present.");
		}
	}
	
	private String algo;
	
	/**
	 * Creates a new digest with the specified salt.
	 * 
	 * @param password
	 *            The password to salt and digest.
	 * @param salt
	 *            The number of bytes in the randomly generated salt.
	 * @param algo
	 *            The message digest algorithm to use.
	 */
	public PasswordMessageDigest(char[] password, String salt, String algo){
		super(password, salt);
		this.algo = algo;
	}
	
	/**
	 * Creates a new digest with a random salt.
	 * 
	 * @param password
	 *            The password to salt and digest
	 * @param saltSize
	 *            The salt to use.
	 * @param algo
	 *            The message digest algorithm to use.
	 */
	public PasswordMessageDigest(char[] password, int saltSize, String algo){
		super(password, saltSize);
		this.algo = algo;
	}
	
	/**
	 * Digests the salt with the password and sets the saltedDigest.
	 */
	@Override
	protected void digest() throws NoSuchAlgorithmException{
		MessageDigest messageDigest = MessageDigest.getInstance(algo);
		messageDigest.reset();
		messageDigest.update(salt);
		byte[] bytes = Charset.forName("UTF-8").encode(CharBuffer.wrap(password)).array();
		messageDigest.update(bytes);
		this.saltedDigest = messageDigest.digest();
	}
	
	public static void main(String[] args) throws Exception{
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Please enter a password to be salted with 256 random bits and hashed with SHA-256:");
		String pass = in.readLine();
		PasswordMessageDigest digest = new PasswordMessageDigest(	pass.toCharArray(),
																	32,
																	MessageDigestAlgorithm.SHA256.algorithm);
		System.out.println("digest: " + digest.getSaltedDigest());
		System.out.println("salt:   " + digest.getSalt());
	}
}
