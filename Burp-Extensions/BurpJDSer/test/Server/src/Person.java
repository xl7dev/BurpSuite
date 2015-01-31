/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */



import java.io.Serializable;
import java.util.List;

/**
 *
 * @author ktran
 */
public class Person implements Serializable {

    private String fname;
    private String lname;
    private List<String> email;
    private int phone;
    private int SSN;



    public Person(String fname, String lname, List<String> email, int phone, int SSN) {
        this.fname = fname;
        this.lname = lname;
        this.email = email;
        this.phone = phone;
        this.SSN = SSN;
    }

    Person() {
        throw new UnsupportedOperationException("Not yet implemented");
    }

    @Override
    public String toString() {
        return "Fistname: " + fname +" \n LastName: " +lname +"\n" ;
    }

}
