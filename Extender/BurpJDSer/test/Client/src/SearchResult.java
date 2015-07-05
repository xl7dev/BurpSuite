


import java.io.Serializable;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */



/**
 *
 * @author ktran
 */
public class SearchResult implements Serializable {

    private Boolean isAdmin;
    private Person person;

    public SearchResult(Boolean isAdmin, Person person) {
        this.isAdmin = isAdmin;
        this.person = person;
    }

    public Boolean getIsAdmin() {
        return isAdmin;
    }

    public Person getPerson() {
        return person;
    }

}
