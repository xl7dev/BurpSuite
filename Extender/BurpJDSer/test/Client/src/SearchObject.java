/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */



import java.io.Serializable;

/**
 *
 * @author ktran
 */
public class SearchObject implements Serializable {

    private String text;

    public SearchObject(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }
    
    
}
