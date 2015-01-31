/*
 * Copyright (C) 2013 DobinRutishauser@broken.ch
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package gui.categorizer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Observable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import util.BurpCallbacks;

/**
 *
 * @author dobin
 */
public class CategorizerManager extends Observable {
    static CategorizerManager categorizerManager;
    static public CategorizerManager getInstance() {
        if (categorizerManager == null) {
            categorizerManager = new CategorizerManager();
        }

        return categorizerManager;
    }
    
    private class StaticCategoriesIndexEntries {
        private String fileName;
        private String tagName;
        
        public StaticCategoriesIndexEntries(String fileName, String tagName) {
            this.fileName = fileName;
            this.tagName = tagName;
        }
                
        public String getFileName() {
            return fileName;
        }
        public String getTagName() {
            return tagName;
        }
    }

    private CategorizerUi categorizerManagerUi;
    private HashMap<String, LinkedList<CategoryEntry>> staticCategories = new HashMap<String, LinkedList<CategoryEntry>>();

    public CategorizerManager() {
        categorizerManagerUi = new CategorizerUi(this);
        
        loadStaticCategories();
    }
    
    public CategorizerUi getCategorizerUi() {
        return categorizerManagerUi;
    }

    public void show() {
        categorizerManagerUi.setVisible(true);
    }
    
    
    public LinkedList<CategoryEntry> getStaticList(String name) {
        if (staticCategories.containsKey(name)) {
            return staticCategories.get(name);
        } else {
            return null;
        }
    }
    
        
    public LinkedList<ResponseCategory> categorize(String input) {
        LinkedList<ResponseCategory> categories = new LinkedList<ResponseCategory>();
        
        if (input == null || input.length() <= 0) {
            return categories;
        }
    
        for(CategoryEntry entry: categorizerManagerUi.getCategories()) {
            categories.addAll(scanForRegex(entry, input));
        }

        for(Map.Entry entry: staticCategories.entrySet()) {
            LinkedList<CategoryEntry> staticCategoriesEntry = (LinkedList<CategoryEntry>) entry.getValue();
            
            for(CategoryEntry e: staticCategoriesEntry) {
                categories.addAll(scanForRegex(e, input));
            }
        }    
        
        return categories;
    }

    
    private LinkedList<ResponseCategory> scanForRegex(CategoryEntry entry, String input) {
        LinkedList<ResponseCategory> categories = new LinkedList<ResponseCategory>();

        Pattern pattern = Pattern.compile(entry.getRegex());
        Matcher matcher = pattern.matcher(input);

        if (matcher.find()) {
            ResponseCategory c = new ResponseCategory(entry, matcher.group(), "Found: " + matcher.group());
            categories.add(c);
        }

        return categories;
    }
    
    
    private void loadStaticCategories() {
        List<StaticCategoriesIndexEntries> staticCategoriesIndex = new ArrayList<StaticCategoriesIndexEntries>();
        staticCategoriesIndex.add(new StaticCategoriesIndexEntries("errors.txt", "error"));
        staticCategoriesIndex.add(new StaticCategoriesIndexEntries("sqlerrors.txt", "sqlerr"));
        
        LinkedList<CategoryEntry> staticCategoryList;
        
        for(StaticCategoriesIndexEntries staticCategory: staticCategoriesIndex) {
            staticCategoryList = new LinkedList<CategoryEntry>();
            InputStream is = getClass().getResourceAsStream("/resources/categories/" + staticCategory.getFileName());
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            
            String line;
            try {
                while ((line = reader.readLine()) != null) {
                    String regex = line;
                    CategoryEntry categoryEntry = new CategoryEntry(staticCategory.getTagName(), Pattern.quote(regex));
                    
                    staticCategoryList.add(categoryEntry);
                }
            } catch (IOException ex) {
                BurpCallbacks.getInstance().print(ex.toString());
            } 
     
            staticCategories.put(staticCategory.getTagName(), staticCategoryList);
        }
    }
    

    void signalModelUpdate() {
        this.setChanged();
        this.notifyObservers();
    }
     
}
