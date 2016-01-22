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
package ddf.catalog.transformer.generic.xml.impl;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.ErrorHandler;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;

import com.vividsolutions.jts.geom.Geometry;
import com.vividsolutions.jts.geom.GeometryFactory;
import com.vividsolutions.jts.io.WKTWriter;
import com.vividsolutions.jts.io.gml2.GMLHandler;

import ddf.catalog.data.Attribute;
import ddf.catalog.data.Metacard;
import ddf.catalog.data.impl.AttributeImpl;
import ddf.catalog.transformer.generic.xml.SaxEventHandler;

public class GmlHandler implements SaxEventHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(GmlHandler.class);

    private List<Attribute> attributes;

    private boolean reading = false;

    GMLHandler gh;

    WKTWriter wktWriter;

    InputStream inputStream;

    public GmlHandler(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    @Override
    public List<Attribute> getAttributes() {
        return attributes;
    }

    @Override
    public List<String> getWatchedElements() {
        return null;
    }

    @Override
    public void setDocumentLocator(Locator locator) {

    }

    @Override
    public void startDocument() throws SAXException {
        gh = new GMLHandler(new GeometryFactory(), (ErrorHandler) null);
        wktWriter = new WKTWriter();
        attributes = new ArrayList<>();

    }

    @Override
    public void endDocument() throws SAXException {

    }

    @Override
    public void startPrefixMapping(String prefix, String uri) throws SAXException {

    }

    @Override
    public void endPrefixMapping(String prefix) throws SAXException {

    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) {
        if (reading || localName.toLowerCase().equals("point")) {
            reading = true;
            try {
                gh.startElement(uri, localName, qName, attributes);
            } catch (SAXException e) {
                LOGGER.debug("GML threw a SAX exception", e);
            }
        }
    }

    @Override
    public void endElement(String namespaceURI, String localName, String qName) {
        if (reading || localName.toLowerCase().equals("point")) {
            reading = true;
            try {
                gh.endElement(namespaceURI, localName, qName);
            } catch (SAXException e) {
                LOGGER.debug("GML threw a SAX exception", e);
            }
        }
        if (localName.toLowerCase().equals("point")) {
            reading = false;
            Geometry geo = gh.getGeometry();
            attributes.add(new AttributeImpl(Metacard.GEOGRAPHY, wktWriter.write(geo)));
        }

    }

    @Override
    public void characters(char[] ch, int start, int length) {
        if (reading) {
            try {
                gh.characters(ch, start, length);
            } catch (SAXException e) {
                LOGGER.debug("GML threw a SAX exception", e);
            }
        }

    }

    @Override
    public void ignorableWhitespace(char[] ch, int start, int length) throws SAXException {

    }

    @Override
    public void processingInstruction(String target, String data) throws SAXException {

    }

    @Override
    public void skippedEntity(String name) throws SAXException {

    }
}
