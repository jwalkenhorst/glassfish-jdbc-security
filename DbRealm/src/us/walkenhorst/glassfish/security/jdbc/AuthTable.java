package us.walkenhorst.glassfish.security.jdbc;
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
public class AuthTable{
	
	public final String tableName;
	
	public final String userCol;
	
	public final String groupCol;
	
	public final String passCol;
	
	public final String saltCol;
	
	public AuthTable(String tableName, String userCol, String groupCol, String passCol,
			String saltCol){
		this.tableName = tableName;
		this.userCol = userCol;
		this.groupCol = groupCol;
		this.passCol = passCol;
		this.saltCol = saltCol;
	}
}