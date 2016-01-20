/**
 * Copyright (c) Codice Foundation
 * <p>
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. A copy of the GNU Lesser General Public License
 * is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */

package ddf.catalog.transformer.generic.xml;

import org.xml.sax.Attributes;

public class SaxEventToXmlElementConverter {

    public static StringBuilder toElement(StringBuilder builder, String uri, String localName,
            Attributes atts) {
        builder.append("<").append(uri).append(":").append(localName);
        for (int i = 0; i < atts.getLength(); i++) {
            builder.append(" ");
            if (!atts.getURI(i).isEmpty()) {
                builder.append(atts.getURI(i)).append(":");
            }
            builder.append(atts.getLocalName(i)).append("=\"").append(atts.getValue(i))
                    .append("\"");
        }
        return builder.append(">");
    }

    public static StringBuilder toElement(StringBuilder builder, String uri, String localName) {
        return builder.append("</").append(uri).append(":").append(localName).append(">");
    }

    public static StringBuilder toElement(StringBuilder builder, char[] ch, int start, int length) {
        return builder.append(ch, start, length);
    }
}
