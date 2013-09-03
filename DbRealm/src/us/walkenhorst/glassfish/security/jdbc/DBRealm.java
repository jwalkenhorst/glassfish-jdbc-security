package us.walkenhorst.glassfish.security.jdbc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
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
 * When configuring the realm, the following properties may be set.
 * The default values are in parenthesis, any following values may also be used:
 * jaas-context (DBRealm)
 * dataSource (jdbc/users)
 * digestAlgorithm (PBKDF2) SHA-256 SHA-512
 * digestIterations (1000)
 * tableName (login)
 * userCol (username)
 * groupCol (groupname)
 * passCol (password)
 * saltCol (salt)
 * 
 * @author jwalkenhorst
 */
public class DBRealm extends AppservRealm{
	
	private String jaasCtxName;
	
	private DBAuthenticate auth;
	
	/**
	 * Init realm from properties
	 * 
	 * @param props
	 * @throws BadRealmException
	 * @throws NoSuchRealmException
	 */
	@Override
	protected synchronized void init(Properties props)
			throws BadRealmException, NoSuchRealmException{
		jaasCtxName = props.getProperty("jaas-context", "DBRealm");
		String dataSourceJndi = props.getProperty("dataSource", "jdbc/users");
		String digestAlgorithm = props.getProperty("digestAlgorithm", "PBKDF2");
		String tableName = props.getProperty("tableName", "login");
		String userCol = props.getProperty("userCol", "username");
		String groupCol = props.getProperty("groupCol", "groupname");
		String passCol = props.getProperty("passCol", "password");
		String saltCol = props.getProperty("saltCol", "salt");
		AuthTable table = new AuthTable(tableName, userCol, groupCol, passCol, saltCol);
		try{
			String digestIterations = props.getProperty("digestIterations");
			int iterations = digestIterations == null ? 1000 : Integer.parseInt(digestIterations);
			auth = new DBAuthenticate(dataSourceJndi, digestAlgorithm, iterations, table);
		} catch (Exception e){
			throw new BadRealmException(e);
		}
	}
	
	public DBAuthenticate getDBAuthenticate(){
		return this.auth;
	}
	
	@Override
	public synchronized String getJAASContext(){
		return jaasCtxName;
	}
	
	@Override
	public String getAuthType(){
		return "Salted PW DB";
	}
	
	@Override
	public Enumeration<String> getGroupNames(String username)
			throws InvalidOperationException, NoSuchUserException{
		String[] userGroups = auth.getUserGroups(username);
		if (userGroups == null) throw new NoSuchUserException(username + " not found");
		List<String> list = new ArrayList<>(userGroups.length);
		for (String s : userGroups){
			list.add(s);
		}
		return Collections.enumeration(list);
	}
}
