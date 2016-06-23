/**
 * Copyright (c) Codice Foundation
 *
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. A copy of the GNU Lesser General Public License
 * is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 *
 **/
/*global define*/
/*jshint -W024*/
define([
    'backbone',
    'underscore',
    'js/model/FieldDescriptors.js',
    'js/model/Field.js',
    'jquery',
    'backboneassociation'


], function (Backbone, _, FieldDescriptors, Field) {

    var counter = 0;

    function addValueFields(field, values) {
        var properties = {};
        properties.value = values;
        if (_.isArray(values)) {
            for (var i = 0; i < values.length; i++) {
                properties['value' + i] = values[i];
            }
        } else if (values && field.get('type') === 'date') {
            var normalizedDateTime = new Date(values).toISOString();
            var dateTimeParts = normalizedDateTime.split('T');
            properties.valueDate = dateTimeParts[0];
            if (dateTimeParts.length === 2) {
                properties.valueTime = dateTimeParts[1].substring(0, dateTimeParts[1].length - 1);
            }
        } else if (values && field.get('type') === 'point') {
            properties.valueLat = values.coords[1];
            properties.valueLon = values.coords[0];
        }
        field.set(properties);
    }

    function addSlotFields(array, backingData, descriptors, segId) {

        var addedSlots = [];
        _.each(_.keys(descriptors), function (name) {
            var entry = descriptors[name];
            if (entry.isSlot) {
                var field = new Field.FormField({
                    key: name,
                    name: entry.displayName,
                    desc: entry.description,
                    type: entry.type,
                    isSlot: true,
                    required: entry.required ? entry.required : false,
                    multiValued: entry.multiValued ? entry.multiValued : false,
                    min: entry.min,
                    max: entry.max,
                    regex: entry.regex,
                    regexMessage: entry.regexMessage,
                    possibleValues: entry.possibleValues,
                    editable: entry.editable,
                    parentId: segId
                });
                var slotFound = false;
                _.each(backingData.Slot, function (slot) {
                    if (slot.name === name) {
                        slotFound = true;
                        var values = getSlotValue(slot, entry.type, entry.multiValued);
                        if(!values || (_.isArray(values) && values.length === 0)) {
                            if(entry.values){
                                if(_.isArray(entry.values)){
                                    values = entry.values.slice(0);
                                } else {
                                    values = entry.values;
                                }
                            }
                        }
                        addValueFields(field, values);
                        addedSlots.push(name);
                    }
                });
                if(!slotFound && entry.values){
                    var values = [];
                    if(_.isArray(entry.values)){
                        values = entry.values.slice(0);
                    } else {
                        values = entry.values;
                    }
                    addValueFields(field, values);
                }
                field.on('change', field.validate, field);
                array.push(field);
            }
        });

        //add custom slots
        _.each(backingData.Slot, function (slot) {
            if (!_.contains(addedSlots, slot.name)) {
                var type = FieldDescriptors.getFieldType(slot.slotType);
                if (!type) {
                    type = slot.slotType;
                }
                var field = new Field.FormField({
                    key: slot.name,
                    name: slot.name,
                    type: type,
                    custom: true,
                    isSlot: true,
                    multiValued: type === 'string',
                    parentId: segId
                });
                addValueFields(field, getSlotValue(slot, type, field.get('multiValued')));
                field.on('change', field.validate, field);
                array.push(field);
            }
        });
    }

    function getSlotValue(slot, type, multiValued) {
        if (_.isArray(slot.value)) { //ebrim value list
            if (multiValued) {
                return slot.value.slice(0);
            }if (type === 'boolean') {
                return slot.value[0] === 'true' ? true : false;
            }
            return slot.value[0];
        } else {
            if (type === 'boolean') {
                return slot.value === 'true' ? true : false;
            } else if (type === 'point') {
                return {coords: slot.value.Point.pos.split(/[ ]+/)};
            } else {
                return slot.value;
            }
        }
    }

    function generateId() {
        counter++;
        return 'urn:segment:id:' + new Date().getTime() + "-" + counter;

    }

    function getSegment(data, key) {
        var backingData = data;
        if (!_.isArray(data)) {
            backingData = [data];
        }
        for (var index = 0; index < backingData.length; index++) {
            var foundModel;

            if (backingData[index].id === key) {
                return backingData[index];
            }

            for (var prop in backingData[index]) {
                if (backingData[index].hasOwnProperty(prop) && typeof backingData[index][prop] === 'object') {
                    foundModel = getSegment(backingData[index][prop], key);
                    if (foundModel) {
                        return foundModel;
                    }
                }
            }
        }
    }

    var Segment = {};

    Segment.Segment = Backbone.AssociatedModel.extend({
        relations: [
            {
                type: Backbone.Many,
                key: 'segments',
                collectionType: function () {
                    return Segment.Segments;
                },
                relatedModel: function () {
                    return Segment.Segment;
                }
            },
            {
                type: Backbone.Many,
                key: 'fields',
                collectionType: function () {
                    return Field.FormFields;
                },
                relatedModel: function () {
                    return Field.FormField;
                }
            }
        ],
        defaults: {
            parentId: undefined,
            simpleId: undefined,
            segmentId: undefined,
            segmentName: undefined,
            segmentType: undefined,
            containerOnly: false,
            multiValued: false,
            editableSegment: true,
            nestedLevel: 0,
            fields: [],
            segments: [],
            associationModel: undefined
        },
        populateFromModel: function (backingData, descriptors) {
            var model = this;
            var segs = [];
            var seg;
            var segType = model.get('segmentType');
            var properties = {
                backingData: backingData,
                descriptors: descriptors
            };

            if (_.isArray(backingData)) {
                properties.segmentId = generateId();
                properties.simpleId = properties.segmentId.split(':').join('-');

                for (var index = 0; index < backingData.length; index++) {
                    seg = new Segment.Segment({
                        segmentName: segType,
                        multiValued: false,
                        parentId: properties.segmentId,
                        segmentType: segType,
                        nestedLevel: model.get('nestedLevel') + 1,
                        associationModel: model.get('associationModel')
                    });
                    seg.constructTitle = model.constructTitle;
                    seg.populateFromModel(backingData[index] ? backingData[index] : {}, descriptors);
                    segs.push(seg);
                }
                properties.segments = segs;
            } else if (backingData) {
                if (backingData.id) {
                    properties.segmentId = backingData.id;
                } else {
                    properties.segmentId = generateId();
                    backingData.id = properties.segmentId;
                }
                properties.simpleId = properties.segmentId.split(':').join('-');

                var fieldList = [];
                var prop;

                for (prop in descriptors[segType]) {
                    if (descriptors[segType].hasOwnProperty(prop)) {
                        var obj = descriptors[segType][prop];
                        if (obj.isGroup) {
                            seg = new Segment.Segment({
                                segmentName: obj.displayName,
                                multiValued: obj.multiValued,
                                parentId: properties.segmentId,
                                segmentType: prop,
                                containerOnly: FieldDescriptors.isContainerOnly(prop),
                                nestedLevel: model.get('nestedLevel') + 1,
                                associationModel: model.get('associationModel'),
                                autoPopulateFunction: obj.autoPopulateFunction,
                                autoPopulateId: obj.autoPopulateId,
                                autoPopulateName: obj.autoPopulateName
                            });
                            seg.constructTitle = obj.constructTitle;
                            var passedModel = backingData[prop];
                            if (!passedModel) {
                                passedModel = seg.get('containerOnly') || obj.multiValued ? [] : {};
                                backingData[prop] = passedModel;
                            }
                            seg.populateFromModel(passedModel, descriptors);
                            segs.push(seg);
                        } else if (!obj.isSlot) {
                            var field =new Field.FormField({
                                key: prop,
                                name: obj.displayName,
                                desc: obj.description,
                                type: obj.type,
                                isSlot: false,
                                multiValued: obj.multiValued,
                                value: backingData[prop] ? backingData[prop] : obj.values,
                                required: obj.required ? obj.required : false,
                                min: obj.min,
                                max: obj.max,
                                regex: obj.regex,
                                regexMessage: obj.regexMessage,
                                possibleValues: obj.possibleValues,
                                editable: obj.editable,
                                parentId: properties.segmentId
                            });
                            field.on('change', field.validate, field);
                            fieldList.push(field);

                        }
                    }
                }
                addSlotFields(fieldList, backingData, descriptors[segType], properties.segmentId);
                properties.segments = segs;
                properties.fields = fieldList;
            } else {
                properties.segmentId = generateId();
                properties.simpleId = properties.segmentId.split(':').join('-');
            }
            model.set(properties);
        },
        addField: function (key, type, value) {
            var model = this;
            if(this.getField(key)){
                //field with that name already exists return
                return;
            }
            var newField = new Field.FormField({
                key: key,
                name: key,
                type: type,
                custom: true,
                isSlot: true,
                multiValued: type === 'string',
                value: [],
                parentId: model.get('segmentId')
            });
            if (value) {
                this.setFieldValue(newField, value);
            }
            newField.on('change', newField.validate, newField);
            this.get('fields').add(newField);
            return newField;
        },
        removeField: function (key) {
            var removedField = _.find(this.get('fields').models, function (field) {
                return field.get('key') === key;
            });
            this.get('fields').remove(removedField);
            return removedField;
        },
        addSegment: function (prePopulateId) {
            var seg = new Segment.Segment({
                segmentName: this.get('segmentName'),
                multiValued: false,
                segmentType: this.get('segmentType'),
                parentId: this.get('segmentId'),
                nestedLevel: this.get('nestedLevel') + 1,
                associationModel: this.get('associationModel')
            });
            seg.constructTitle = this.constructTitle;
            seg.populateFromModel({}, this.get('descriptors'));
            if (this.get('autoPopulateFunction') && prePopulateId) {
                this.get('autoPopulateFunction')(seg, this.getAutoPopulationValues(prePopulateId));
            }
            this.get('segments').add(seg);
            var segTitle = seg.constructTitle ? seg.constructTitle() : seg.getField('Name').get('value');
            this.get('associationModel').addAssociationSegment(seg.get('segmentId'), seg.get('segmentType'), segTitle);

            return seg;
        },
        removeSegment: function (id) {
            var seg = _.find(this.get('segments').models, function (seg) {
                return seg.get('segmentId') === id;
            });
            this.get('segments').remove(seg);
            this.get('associationModel').removeSegment(seg);
            return seg;
        },
        setFieldValue: function (field, value) {
            addValueFields(field, value);
        },
        getField: function (key) {
            var fields = this.get("fields").models;
            var foundField;
            _.each(fields, function (field) {
                if (field.get('key') === key) {
                    foundField = field;
                }
            });
            return foundField;
        },
        getAutoPopulationValues: function (prePopulateId) {
            var autoPopId = this.get('autoPopulateId');
            var autoPopObj = FieldDescriptors.autoPopulateValues[this.get('segmentType')];
            return _.find(autoPopObj, function (obj) {
                return obj[autoPopId] === prePopulateId;
            });
        },
        validate: function(){
            var errors = [];
            var fields = this.get("fields").models;
            var segments = this.get('segments').models;
            this.validationError = undefined;
            _.each(fields, function (field) {
                var error = field.validate();
                if(error){
                    errors = errors.concat(error);
                }
            });

            _.each(segments, function (segment) {
                var error = segment.validate();
                if(error){
                    errors = errors.concat(error);
                }
            });
            if(errors.length > 0){
                this.validationError = errors;
                return errors;
            }
        },
        saveData: function () {
            var model = this;
            var fields = this.get("fields").models;
            var segments = this.get('segments').models;
            var ebrimTypes = FieldDescriptors.getSlotTypes();
            var backingData = model.get('backingData');
            if (!backingData.Slot) {
                backingData.Slot = [];
            }
            //update and add values
            _.each(fields, function (field) {
                field.saveData(backingData,ebrimTypes);
            });

            //remove slots
            if (backingData.Slot) {
                var slots = [];
                for (var index = 0; index <backingData.Slot.length; index++) {
                    if (model.getField(backingData.Slot[index].name)) {
                        slots.push(backingData.Slot[index]);
                    }
                }
                backingData.Slot = slots;
            }

            //now handle the segments
            _.each(segments, function (segment) {
                if (!segment.get('containerOnly') && !segment.get('multiValued')) {
                    var segObj = getSegment(backingData, segment.get('segmentId'));
                    if (!segObj) {
                        if (!_.isArray(backingData)) {
                            backingData[segment.get('segmentType')] = segment.get('backingData');
                        }
                    }
                }
                segment.saveData();
            });
            if (_.isArray(backingData)) {
                backingData.length = 0;
                _.each(segments, function (segment) {
                    backingData.push(segment.get('backingData'));
                });
            }
        }
    });

    Segment.Segments = Backbone.Collection.extend({
        model: Segment.Segment
    });

    return Segment;
});