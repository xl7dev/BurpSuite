/*
* Copyright 2011 the original author or authors.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package org.apache.jmeter.protocol.amf.util;

import java.util.Iterator;
import java.util.Map;

import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.converters.collections.AbstractCollectionConverter;
import com.thoughtworks.xstream.io.ExtendedHierarchicalStreamWriterHelper;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import com.thoughtworks.xstream.mapper.Mapper;

import flex.messaging.io.amf.ASObject;

public class ASObjectConverter extends AbstractCollectionConverter {
	
	private static final String SERIAL_VER_1 = "1";

	private final String currSerialVer = SERIAL_VER_1;

	public ASObjectConverter(Mapper mapper) {
		super(mapper);
	}

	@SuppressWarnings("rawtypes")
	@Override
	public boolean canConvert(Class clazz) {
		return clazz.equals(ASObject.class);
	}

	@SuppressWarnings({ "rawtypes" })
	@Override
	public void marshal(Object obj, HierarchicalStreamWriter writer,
			MarshallingContext context) {
		ASObject asObj = (ASObject) obj;
		
		writer.addAttribute("serialVer", currSerialVer);
		
		if (asObj.getType() != null)
			writer.addAttribute("objClass", asObj.getType());
		
		for (Iterator iterator = asObj.entrySet().iterator(); iterator.hasNext();) {
            Map.Entry entry = (Map.Entry) iterator.next();
            ExtendedHierarchicalStreamWriterHelper.startNode(writer, mapper().serializedClass(Map.Entry.class), Map.Entry.class);

            writeItem(entry.getKey(), context, writer);
            writeItem(entry.getValue(), context, writer);

            writer.endNode();
        }
	}
	
	// TODO: If serialization changes
	//public void marshal_v1(Object obj, HierarchicalStreamWriter writer,
	//		MarshallingContext context) {
	//	
	//}

	public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
		ASObject asObj = new ASObject();
		
		String type = reader.getAttribute("objClass");
		if (type != null) {
			asObj.setType(type);
		}
		
        populateMap(reader, context, asObj);
        
        return asObj;
    }
	
	// TODO: If serialization changes
	//public Object unmarshal_v1(HierarchicalStreamReader reader, UnmarshallingContext context) {
	//	return null;
	//}

    @SuppressWarnings("unchecked")
	protected void populateMap(HierarchicalStreamReader reader, UnmarshallingContext context, ASObject map) {
        while (reader.hasMoreChildren()) {
            reader.moveDown();

            reader.moveDown();
            Object key = readItem(reader, context, map);
            reader.moveUp();

            reader.moveDown();
            Object value = readItem(reader, context, map);
            reader.moveUp();

            map.put(key, value);

            reader.moveUp();
        }
    }

}
