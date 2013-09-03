package us.walkenhorst.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.xml.bind.DatatypeConverter;

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
public abstract class PasswordDigest{
	
	protected char[] password;
	
	protected byte[] salt;
	
	protected byte[] saltedDigest;
	
	protected abstract void digest() throws NoSuchAlgorithmException;
	
	/**
	 * Creates a new digest with the specified salt.
	 * 
	 * @param password
	 *            The password to salt and digest.
	 * @param salt
	 *            The salt to use. Pass in "" if no salt is desired.
	 */
	public PasswordDigest(char[] password, String salt){
		this.password = password;
		setSalt(salt);
	}
	
	/**
	 * Creates a new digest with a random salt.
	 * 
	 * @param password
	 *            The password to salt and digest
	 * @param saltSize
	 *            The number of bytes in the randomly generated salt. Pass in zero if no salt is desired.
	 */
	public PasswordDigest(char[] password, int saltSize){
		this.password = password;
		generateSalt(saltSize);
	}
	
	/**
	 * @return a base64 encoded string of the salt bytes, or null if no salt was set. The encoded string conforms to
	 *         lexical value space defined in XML Schema Part 2: Datatypes for xsd:base64Binary
	 */
	public String getSalt(){
		if (salt == null) return null;
		return DatatypeConverter.printBase64Binary(salt);
	}
	
	/**
	 * @param salt
	 *            A base64 endoding of the salt bytes.
	 * @throws IllegalArgumentException
	 *             if salt does not conform to lexical value space defined in XML Schema Part 2: Datatypes
	 *             for xsd:base64Binary
	 */
	protected void setSalt(String salt){
		this.salt = DatatypeConverter.parseBase64Binary(salt);
	}
	
	/**
	 * Sets this PasswordDigest's salt to a random salt with the specified size.
	 * 
	 * @param saltSize
	 *            the size in bytes of the generated salt.
	 * @throws IllegalArgumentException
	 *             if the saltSize is negative
	 */
	protected void generateSalt(int saltSize){
		if (saltSize < 0) throw new IllegalArgumentException();
		SecureRandom rand = new SecureRandom();
		salt = new byte[saltSize];
		rand.nextBytes(salt);
	}
	
	/**
	 * Gets the saltedDigest of this PasswordDigest. If the digest() method has not been called on this PasswordDigest,
	 * it will be called prior to returning the saltedDigest. The salt must be set prior to calling this method.
	 * 
	 * @returna base64 encoded string of the saltedDigest. The encoded string conforms to lexical value space defined in
	 *          XML Schema Part 2: Datatypes for xsd:base64Binary
	 */
	public String getSaltedDigest() throws NoSuchAlgorithmException{
		if (saltedDigest == null){
			this.digest();
		}
		return DatatypeConverter.printBase64Binary(this.saltedDigest);
	}
}