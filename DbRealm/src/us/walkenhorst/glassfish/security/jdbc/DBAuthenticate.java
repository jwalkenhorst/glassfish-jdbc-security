package us.walkenhorst.glassfish.security.jdbc;

import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import us.walkenhorst.crypto.PBEDigest;
import us.walkenhorst.crypto.PasswordDigest;
import us.walkenhorst.crypto.PasswordMessageDigest;
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
 * Helper class to connect to authentication database using JDBC and JNDI 
 */
public class DBAuthenticate{
	
	private DataSource dataSource;
	
	private String datasourceJdni;
	
	private String algorithm;
	
	private int iterations;
	
	private String groupQuery;
	
	private String authQuery;
	
	private String saltQuery;
	
	public DBAuthenticate(String datasourceJdni, String algorithm, int iterations, AuthTable table){
		if (!isSupported(algorithm)) throw new IllegalArgumentException("algorithm not supported: "+algorithm);
		if (iterations < 1) throw new IllegalArgumentException("iterations must be positive: "+iterations);
		this.algorithm = algorithm;
		this.iterations = iterations;
		this.datasourceJdni = datasourceJdni;
		initGroupQuery(table);
		initAuthQuery(table);
		initSaltQuery(table);
	}
	
	private void initGroupQuery(AuthTable table){
		groupQuery = "SELECT "
				+ table.groupCol
				+ " FROM "
				+ table.tableName
				+ " WHERE "
				+ table.userCol
				+ " = ?;";
	}
	
	private void initAuthQuery(AuthTable table){
		authQuery = "SELECT "
				+ table.groupCol
				+ " FROM "
				+ table.tableName
				+ " WHERE "
				+ table.userCol
				+ " = ? AND "
				+ table.passCol
				+ " = ?;";
	}
	
	private String initSaltQuery(AuthTable table){
		return saltQuery = "SELECT "
				+ table.saltCol
				+ " FROM "
				+ table.tableName
				+ " WHERE "
				+ table.userCol
				+ " = ? LIMIT 1;";
	}
	
	private DataSource getDataSource() throws NamingException{
		if (this.dataSource == null){
			Context ctx = null;
			ctx = new InitialContext();
			dataSource = (DataSource)ctx.lookup(datasourceJdni);
			try{
				ctx.close();
			} catch (NamingException e){
				e.printStackTrace();
			}
		}
		return this.dataSource;
	}
	
	public PasswordDigest getDigest(char[] password, String salt){
		PasswordDigest digest = null;
		if (PBEDigest.ALGORITHM.equals(algorithm)){
			digest = new PBEDigest(password, salt, iterations);
		} else{
			digest = new PasswordMessageDigest(password, salt, algorithm);
		}
		return digest;
	}
	
	public static boolean isSupported(String algo){
		return PBEDigest.ALGORITHM.equals(algo)
				|| PasswordMessageDigest.MessageDigestAlgorithm.isSupported(algo);
	}
	
	public String[] getUserGroups(String name){
		String[] groups = null;
		try (Connection con = getDataSource().getConnection()){
			PreparedStatement statement = con.prepareStatement(groupQuery);
			statement.setString(1, name);
			ResultSet rs = statement.executeQuery();
			List<String> groupList = new ArrayList<>();
			boolean found = false;
			while (rs.next()){
				found = true;
				String group = rs.getString(1);
				if (group != null) groupList.add(group);
			}
			if (found) groups = groupList.toArray(new String[0]);
		} catch (SQLException | NamingException ex){
			ex.printStackTrace();
		}
		return groups;
	}
	
	public String[] getUserGroups(String name, char[] password){
		String salt = getSaltForUser(name);
		String[] groups = null;
		if (salt != null){
			PasswordDigest digest = getDigest(password, salt);
			try (Connection con = getDataSource().getConnection()){
				PreparedStatement statement = con.prepareStatement(authQuery);
				statement.setString(1, name);
				statement.setString(2, digest.getSaltedDigest());
				ResultSet rs = statement.executeQuery();
				List<String> groupList = new ArrayList<>();
				boolean found = false;
				while (rs.next()){
					found = true;
					String group = rs.getString(1);
					if (group != null) groupList.add(group);
				}
				if (found) groups = groupList.toArray(new String[0]);
			} catch (SQLException | NamingException | NoSuchAlgorithmException ex){
				ex.printStackTrace();
			}
		}
		return groups;
	}
	
	private String getSaltForUser(String name){
		String salt = null;
		try (Connection con = getDataSource().getConnection()){
			PreparedStatement statement = con.prepareStatement(saltQuery);
			statement.setString(1, name);
			ResultSet rs = statement.executeQuery();
			if (rs.next()){
				salt = rs.getString(1);
			}
		} catch (SQLException | NamingException ex){
			ex.printStackTrace();
		}
		return salt;
	}
}
