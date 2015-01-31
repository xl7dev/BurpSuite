/*
* Copyright 2004 The Apache Software Foundation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
/* $Id$
 *
 */

import java.io.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * The simplest possible servlet.
 *
 * @author James Duncan Davidson
 */

public class HelloWorldExample extends HttpServlet {
public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
{
        try {
 Person person = null;
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        SearchObject searchReq= (SearchObject) in.readObject();

            List<String>emails=new ArrayList<String>();
            emails.add("test@user.com");
            person = new Person("test","user",emails,234,123);
if (searchReq.getText().contains("' or 1=1--"))
                person = new Person("test1","user1",emails,234,123);

            response.reset();
            response.setHeader("Content-Type", "application/x-java-serialized-object");
SearchResult result=new SearchResult(Boolean.FALSE, person);
            ObjectOutputStream outputToApplet;
            outputToApplet = new ObjectOutputStream(response.getOutputStream());
            outputToApplet.writeObject(result);
            outputToApplet.flush();
            outputToApplet.close();
        } catch (Exception ex) {
            Logger.getLogger(HelloWorldExample.class.getName()).log(Level.SEVERE, null, ex);
        }
}

private Person processSomething(HttpServletRequest request) throws IOException, ClassNotFoundException
{
  ObjectInputStream inputFromApplet = new ObjectInputStream(request.getInputStream());
  Person myObject = (Person) inputFromApplet.readObject();
  //Do Something with the object you just passed
  Person myrespObj= new Person();
  return myObject;
}

    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
        throws IOException, ServletException
    {
       Person myrespObj = null;
      
            List<String>emails=new ArrayList<String>();
            emails.add("test@user.com");
            myrespObj = new Person("test","user",emails,234,123);
        
            response.reset();
            response.setHeader("Content-Type", "application/x-java-serialized-object");
            ObjectOutputStream outputToApplet;
            outputToApplet = new ObjectOutputStream(response.getOutputStream());
            outputToApplet.writeObject(myrespObj);
            outputToApplet.flush();
            outputToApplet.close();

	// note that all links are created to be relative. this
	// ensures that we can move the web application that this
	// servlet belongs to to a different place in the url
	// tree and not have any harmful side effects.

        // XXX
        // making these absolute till we work out the
        // addition of a PathInfo issue

	
    }
}



