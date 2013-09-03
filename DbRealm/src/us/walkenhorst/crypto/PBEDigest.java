package us.walkenhorst.crypto;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
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
/**
 * Hashes the password using PBKDF2.
 * 
 */
public class PBEDigest extends PasswordDigest{
	
	public static final String ALGORITHM = "PBKDF2";
	
	private static final String KEY_FACTORY = "PBKDF2WithHmacSHA1"; //from http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html
	
	private int iterations;
	
	private static final int KEY_BYTES = 24;
	
	private static final int SALT_BYTES = KEY_BYTES;
	
	public PBEDigest(char[] password, int iterations){
		super(password, SALT_BYTES);
		this.iterations = iterations;
	}
	
	public PBEDigest(char[] password, String salt, int iterations){
		super(password, salt);
		this.iterations = iterations;
	}
	
	@Override
	protected void digest() throws NoSuchAlgorithmException{
		PBEKeySpec spec = new PBEKeySpec(this.password, this.salt, iterations, KEY_BYTES * 8);
		SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY);
		try{
			this.saltedDigest = factory.generateSecret(spec).getEncoded();
		} catch (InvalidKeySpecException e){
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) throws Exception{
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Please enter a password to be salted and hashed:");
		String pass = in.readLine();
		char[] charArray = pass.toCharArray();
		int iterations = 1000;
		PBEDigest digest = new PBEDigest(charArray, iterations); //throwaway instantiation to time without JIT
		long start = System.currentTimeMillis();
		digest = new PBEDigest(charArray, iterations);
		String saltedDigest = digest.getSaltedDigest();
		long stop = System.currentTimeMillis();
		System.out.println("digest: " + saltedDigest);
		System.out.println("salt:   " + digest.getSalt());
		System.out.println("milis:  " + (stop - start));
	}
}
