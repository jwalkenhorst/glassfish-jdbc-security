glassfish-jdbc-security
=======================
This goal of this project is to create a Glassfish realm that authenticates against a database.
Additionally, strong security techniques such as hashing and salting are used to increase security.

Overview:
There are two packages:
	us.walkenhorst.crypto - includes utility classes for hashing and salting passwords.
	us.walkenhorst.glassfish.security.jdbc - defines a custom glassfish realm,
                                             login module, and  helper classes

Build Dependencies:
You must add appserv-rt.jar from your \glassfish\lib folder to the build path to compile the
DBLogin and DBRealm classes in the us.walkenhorst.glassfish.security.jdbc package.

Deployment:
1) Compile both packages and put them in a JAR file.
2) Add the JAR file to your Glassfish's \glassfish\lib folder while Glassfish is not running.
3) You must specify the login module to use with the realm.
   Open the login.conf file in the \glassfish\domains\domain1\config directory.
   Add the following lines at the end of the file and save:

	DBRealm{
		us.walkenhorst.glassfish.security.jdbc.DBLogin required;
	};
 
4) Start Glassfish and open the admin console on http://localhost:4848
5) Create a new realm under Configurations, server-config, Security, Realms
5a) The name field of the new realm can be anything you want.
5b) For the "Class Name" option, check the lower radio button and enter us.walkenhorst.glassfish.security.jdbc.DBRealm
5c) For each of the following settings, click "Add Property" and add a new name/value pair (if you want a non-default value).
    The default values are in parenthesis, other valid values are listed after the default.
```
		jaas-context (DBRealm)
		dataSource (jdbc/users)
		digestAlgorithm (PBKDF2) SHA-256 SHA-512
		digestIterations (1000)
		tableName (login)
		userCol (username)
		groupCol (groupname)
		passCol (password)
		saltCol (salt)
```
	The jaas-context value should probably always use the default value.
	dataSource refers to the JNDI name of the JDBC connection poolto use for authentication.
	digestIterations only matters if the digestAlgorithm is PBKDF2. It is ignored otherwise.
	For the remaining properties, the realm expects a single table to have the
	username, password, salt, and groupname	for each user.
	If a user belongs to more than one group, then there should be multiple rows for that user,
	one row for each group he/she belongs to.
	For a database in 2nd normal form (i.e. separate tables for users and groups, with a mapping table
	that joins them), I recommend creating a view that left joins users to groups using
	the mapping table. For example:
```
	CREATE VIEW `login` AS
		SELECT `u`.`name` AS `username`,`u`.`password` AS `password`,`u`.`salt` AS `salt`,`g`.`name` AS `groupname`
		FROM ((`users` `u` LEFT JOIN `users_groups` `ug` ON((`u`.`user_id` = `ug`.`user_id`)))
		LEFT JOIN `groups` `g` ON((`ug`.`group_id` = `g`.`group_id`)));
```
5d) Save the new realm. It is now ready to be used. 
