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
package ddf.catalog.transformer.generic.xml.lib;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Stack;

import org.apache.commons.io.input.TeeInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

import ddf.catalog.data.Attribute;
import ddf.catalog.data.Metacard;
import ddf.catalog.data.MetacardType;
import ddf.catalog.data.impl.AttributeImpl;
import ddf.catalog.data.impl.MetacardImpl;
import ddf.catalog.transformer.generic.xml.SaxEventHandler;

public class SaxEventHandlerDelegate extends DefaultHandler {

    private static XMLReader parser;

    private List<SaxEventHandler> eventHandlers = new ArrayList<>();

    private Map<String, List<SaxEventHandler>> eventHandlerLookup = new HashMap<>();

    private InputStream stream;

    private static final Logger LOGGER = LoggerFactory.getLogger(SaxEventHandlerDelegate.class);

    private MetacardType metacardType;

    public SaxEventHandlerDelegate() {
        try {
            // Read set up
            //            SAXParserFactory factory = SAXParserFactory.newInstance();
            //
            //            factory.setSchema(null);
            //            factory.setNamespaceAware(true);
            //            factory.setValidating(false);
            //            //            factory.setFeature("http://xml.org/sax/features/namespaces", false);
            //            factory.setFeature("http://xml.org/sax/features/validation", false);
            //            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar",
            //                    false);
            //            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd",
            //                    false);
            //
            //            parser = factory.newSAXParser();
            parser = XMLReaderFactory.createXMLReader();
        } catch (Exception e) {
            LOGGER.debug(
                    "Exception thrown during creation of SaxEventHandlerDelegate. Probably caused by one of the setFeature calls",
                    e);
        }
    }

    public SaxEventHandlerDelegate(SaxEventHandler... eventHandlers) {
        this();
        this.eventHandlers = Arrays.asList(eventHandlers);
    }

    public SaxEventHandlerDelegate(List<SaxEventHandler> eventHandlers) {
        this();
        this.eventHandlers = eventHandlers;
    }

    public Metacard read(InputStream inputStream) {
        configureEventHandlerLookup();
        Metacard metacard = new MetacardImpl(metacardType);
        try {
            stream = inputStream;
            InputSource newStream = new InputSource(new BufferedInputStream(inputStream));
            parser.setContentHandler(this);
            parser.parse(newStream);
            //parser.parse(new BufferedInputStream(inputStream), this);
        } catch (IOException | SAXException e) {
            LOGGER.debug("Exception thrown during parsing of inputStream", e);
        }

        // Populate metacard with all attributes constructed in SaxEventHandlers during parsing
        for (SaxEventHandler eventHandler : eventHandlers) {
            List<Attribute> attributes = eventHandler.getAttributes();
            for (Attribute attribute : attributes) {
                Attribute tmpAttr = metacard.getAttribute(attribute.getName());
                if (tmpAttr != null) {
                    List<Serializable> tmpAttrValues = tmpAttr
                            .getValues(); //.stream().filter(Objects::nonNull).collect(Collectors.toList());

                    tmpAttrValues.addAll(attribute.getValues());
                    tmpAttr = new AttributeImpl(attribute.getName(), tmpAttrValues);
                    metacard.setAttribute(tmpAttr);

                } else {
                    metacard.setAttribute(attribute);
                }
            }
        }
        return metacard;
    }

    @Override
    public void startDocument() {
        for (SaxEventHandler transformer : eventHandlers) {
            try {
                transformer.startDocument();
            } catch (SAXException e) {
                LOGGER.debug("Sax Exception thrown during startDocument event", e);
            }
        }
    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes)
            throws SAXException {
        for (SaxEventHandler transformer : eventHandlers) {
            transformer.startElement(uri, localName, qName, attributes);
        }

    }

    @Override
    public void characters(char ch[], int start, int length) throws SAXException {
        for (SaxEventHandler transformer : eventHandlers) {
            transformer.characters(ch, start, length);
        }
    }

    @Override
    public void endElement(String namespaceURI, String localName, String qName)
            throws SAXException {

        for (SaxEventHandler transformer : eventHandlers) {
            transformer.endElement(namespaceURI, localName, qName);
        }

    }

    private void configureEventHandlerLookup() {

        for (SaxEventHandler eventHandler : eventHandlers) {
            for (String element : eventHandler.getWatchedElements()) {
                List<SaxEventHandler> tmpList = eventHandlerLookup.get(element) != null ?
                        eventHandlerLookup.get(element) :
                        new ArrayList<>();
                tmpList.add(eventHandler);
                eventHandlerLookup.put(element, tmpList);
            }
        }

    }

    public SaxEventHandlerDelegate setMetacardType(MetacardType metacardType) {
        this.metacardType = metacardType;
        return this;
    }

    public TeeInputStream getMetadataStream(InputStream inputStream, OutputStream outputStream) {
        return new TeeInputStream(inputStream, outputStream);
    }

}
