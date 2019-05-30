/*
 * ARX: Powerful Data Anonymization
 * Copyright 2012 - 2016 Fabian Prasser, Florian Kohlmayer and contributors
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
package org.deidentifier.arx.certificate;

import org.apache.commons.lang.StringUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.deidentifier.arx.*;
import org.deidentifier.arx.ARXLattice.ARXNode;
import org.deidentifier.arx.ARXLattice.Anonymity;
import org.deidentifier.arx.certificate.CertificateStyle.ListStyle;
import org.deidentifier.arx.certificate.elements.*;
import org.deidentifier.arx.criteria.PrivacyCriterion;
import org.deidentifier.arx.io.CSVDataChecksum;
import org.deidentifier.arx.io.CSVSyntax;
import org.deidentifier.arx.risk.RiskEstimateBuilder;
import org.deidentifier.arx.risk.RiskModelAttributes;
import rst.pdfbox.layout.elements.Document;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * A PDF document
 * 
 * @author Annika Saken
 * @author Fabian Prasser
 */
public class RiskReport { // NO_UCD

    /**
     * Creates a new instance
     * @param input
     * @param definition
     * @param config
     * @param result
     * @param transformation
     * @param output
     */
    public static RiskReport create(DataHandle input, DataDefinition definition,
                                    ARXConfiguration config, ARXResult result, ARXNode transformation, DataHandle output) {
        return RiskReport.create(input, definition, config, result, transformation, output, null);
    }

    /**
     * Renders the document into the given output stream.
     * Includes a SHA-256 checksum of the output data.
     *
     * @param input
     * @param definition
     * @param config
     * @param result
     * @param transformation
     * @param output
     * @param syntax
     */
    public static RiskReport create(DataHandle input,
                                    DataDefinition definition,
                                    ARXConfiguration config,
                                    ARXResult result,
                                    ARXNode transformation,
                                    DataHandle output,
                                    CSVSyntax syntax) {
        return RiskReport.create(input, definition, config, result, transformation, output, syntax, null);
    }

    /**
     * Renders the document into the given output stream.
     * Includes a SHA-256 checksum of the output data and user defined metadata
     *
     * @param input
     * @param definition
     * @param config
     * @param result
     * @param transformation
     * @param output
     * @param syntax
     * @param metadata
     */
    public static RiskReport create(DataHandle input,
                                    DataDefinition definition,
                                    ARXConfiguration config,
                                    ARXResult result,
                                    ARXNode transformation,
                                    DataHandle output,
                                    CSVSyntax syntax,
                                    ElementData metadata) {
        return new RiskReport(input, definition, config, result, transformation, output, syntax, metadata);
    }

    /** The document style */
    private final CertificateStyle style;
    /** Elements*/
    private final List<Element> elements = new ArrayList<Element>();

    /**
     * Creates a new instance
     * @param input
     * @param definition
     * @param config
     * @param result
     * @param transformation
     * @param output
     * @param csvConfig
     * @param metadata
     */
    RiskReport(DataHandle input, DataDefinition definition,
               ARXConfiguration config, ARXResult result,
               ARXNode transformation, DataHandle output,
               CSVSyntax csvConfig, ElementData metadata) {
        
        this.style = CertificateStyle.create();

        // Check
        if (input == null || definition == null || config == null || result == null || transformation == null) {
            throw new NullPointerException();
        }

        int section = 1;
        if (metadata != null) {
            this.add(new ElementTitle("Project"));
            this.add(new ElementSubtitle((section++)+". Properties"));
            this.add(asList(metadata));
            this.add(new ElementNewLine());
        }
        section = 1;
        this.add(new ElementTitle("Risk analysis"));

        this.add(new ElementSubtitle((section++)+". Mixed risk analysis"));
        this.add(new ElementNewLine());
//            this.add(new ElementData("this is a test"));
        ARXPopulationModel populationmodel = ARXPopulationModel.create(ARXPopulationModel.Region.USA);
        DataHandle temp_handle = result.getOutput(transformation);
        String prosecutorRisk = String.valueOf(temp_handle.getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedProsecutorRisk());
        String journalistRisk = String.valueOf(temp_handle.getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedJournalistRisk());
        String marketerRisk = String.valueOf(temp_handle.getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedMarketerRisk());
        this.add(new ElementData("Prosecutor risk: " + prosecutorRisk));
        this.add(new ElementData("journalist risk: " + journalistRisk));
        this.add(new ElementData("Marketer risk: " + marketerRisk));

//        analyzeAttributes(input);
        this.add(asList(result.getLattice().render()));
        RiskModelAttributes.QuasiIdentifierRisk[] quasiIdentifiers = analyzeAttributes(input);
        ElementData distinction = new ElementData("Distinction");
        for (RiskModelAttributes.QuasiIdentifierRisk quasiIdentifier : quasiIdentifiers) {
            distinction.addProperty(quasiIdentifier.getIdentifier().toString(), String.valueOf(quasiIdentifier.getDistinction()));
        }
        this.add(asList(distinction));
//        renderQIRisks(attributeRisks);
//        this.add(asList(result.getLattice().render()));
    }

    private void renderQIRisks(RiskModelAttributes.QuasiIdentifierRisk[] quasiIdentifiers){
//        for (RiskModelAttributes.QuasiIdentifierRisk quasiIdentifier : quasiIdentifiers) {
        for(int i =0; i < 10 ; i++){
            RiskModelAttributes.QuasiIdentifierRisk quasiIdentifier = quasiIdentifiers[i];
        // print every Quasi-Identifier
            System.out.println(quasiIdentifier.getIdentifier() + String.valueOf(quasiIdentifier.getDistinction() * 100) + quasiIdentifier.getSeparation() * 100);
        }
    }

    /**
     * Calculate Alpha Distinction and Separation
     *
     * @param handle the data handle
     */
    private static RiskModelAttributes.QuasiIdentifierRisk[] analyzeAttributes(DataHandle handle) {
        ARXPopulationModel populationmodel = ARXPopulationModel.create(ARXPopulationModel.Region.USA);
        RiskEstimateBuilder builder = handle.getRiskEstimator(populationmodel);
        RiskModelAttributes riskmodel = builder.getAttributeRisks();

        // output
        RiskModelAttributes.QuasiIdentifierRisk[] attributeRisks = riskmodel.getAttributeRisks();
//        for(int i = 0; i <10;i++){
//            System.out.println(attributeRisks[i]);
//        }
//        printPrettyTable(attributeRisks);
        return attributeRisks;
    }

    /**
     * Helper that prints a table
     * @param quasiIdentifiers
     */
    private static void printPrettyTable(RiskModelAttributes.QuasiIdentifierRisk[] quasiIdentifiers) {

        // get char count of longest quasi-identifier
        int charCountLongestQi = quasiIdentifiers[quasiIdentifiers.length-1].getIdentifier().toString().length();

        // make sure that there is enough space for the table header strings
        charCountLongestQi = Math.max(charCountLongestQi, 12);

        // calculate space needed
        String leftAlignFormat = "| %-" + charCountLongestQi + "s | %13.2f | %12.2f |%n";

        // add 2 spaces that are in the string above on the left and right side of the first pattern
        charCountLongestQi += 2;

        // subtract the char count of the column header string to calculate
        // how many spaces we need for filling up to the right columnborder
        int spacesAfterColumHeader = charCountLongestQi - 12;

        System.out.format("+" + StringUtils.repeat("-", charCountLongestQi) + "+---------------+--------------+%n");
        System.out.format("| Identifier " + StringUtils.repeat(" ", spacesAfterColumHeader) + "|   Distinction |   Separation |%n");
        System.out.format("+" + StringUtils.repeat("-", charCountLongestQi) + "+---------------+--------------+%n");
        for (RiskModelAttributes.QuasiIdentifierRisk quasiIdentifier : quasiIdentifiers) {
            // print every Quasi-Identifier
            System.out.format(leftAlignFormat, quasiIdentifier.getIdentifier(), quasiIdentifier.getDistinction() * 100, quasiIdentifier.getSeparation() * 100);
        }
        System.out.format("+" + StringUtils.repeat("-", charCountLongestQi) + "+---------------+--------------+%n");
    }

    /**
	 * Renders the document into the given output stream
	 * 
	 * @param file
	 * @throws IOException 
	 */
	public void save(File file) throws IOException {
        FileOutputStream stream = new FileOutputStream(file);
        this.save(stream);
        stream.close();
	}
    /**
     * Renders the document into the given output stream
     * 
     * @param stream
     * @throws IOException 
     */
    public void save(OutputStream stream) throws IOException {
        
        // Render
        Document document = new Document(style.gethMargin(), style.gethMargin(), style.getvMargin(), style.getvMargin());
        for (Element element : this.elements) {
            element.render(document, 0, this.style);
        }
        
        // Save to temp file
        File tmp = File.createTempFile("arx", "src/main/org.deidentifier.arx/certificate");
        document.save(tmp);
        
        // Load and watermark
        PDDocument pdDocument = PDDocument.load(tmp);
//        Watermark watermark = new Watermark(pdDocument);
//        watermark.mark(pdDocument);
        
        // Save
        pdDocument.save(stream);
        pdDocument.close();
        tmp.delete();
    }
    
	/**
     * Renders as a list
     * @param data
     * @return
     */
	private Element asList(ElementData data) {
	    ElementList list = new ElementList(ListStyle.BULLETS);
	    list.addItem(data.asList());
	    return list;
    }

    /**
     * Renders as a list
     * @param data
     * @return
     */
    private Element asList(List<ElementData> data) {
        ElementList list = new ElementList(ListStyle.BULLETS);
        for (ElementData d : data) {
            list.addItem(d.asList());
        }
        return list;
    }
    
	/**
	 * Adds a new element
	 * @param element
	 */
	void add(Element element) {
	    this.elements.add(element);
	}
}
