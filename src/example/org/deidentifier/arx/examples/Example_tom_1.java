/*
 * ARX: Powerful Data Anonymization
 * Copyright 2012 - 2018 Fabian Prasser and contributors
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

package org.deidentifier.arx.examples;

import org.deidentifier.arx.*;
import org.deidentifier.arx.AttributeType.Hierarchy;
import org.deidentifier.arx.criteria.EntropyLDiversity;
import org.deidentifier.arx.io.CSVHierarchyInput;
import org.deidentifier.arx.metric.Metric;
import org.deidentifier.arx.risk.*;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class implements an example on how to use the l-diversity privacy model
 * without protecting sensitive assocations.
 *
 * @author Fabian Prasser
 * @author Florian Kohlmayer
 */
public class Example_tom_1 extends Example {

    /**
     * Loads a dataset from disk
     * @param dataset
     * @return
     * @throws IOException
     */
    public static Data createData(final String dataset) throws IOException {

        Data data = Data.create("data/" + dataset + ".csv", StandardCharsets.UTF_8, ';');

        // Read generalization hierarchies
        FilenameFilter hierarchyFilter = new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                if (name.matches(dataset + "_hierarchy_(.)+.csv")) {
                    return true;
                } else {
                    return false;
                }
            }
        };

        // Create definition
        File testDir = new File("data/");
        File[] genHierFiles = testDir.listFiles(hierarchyFilter);
        Pattern pattern = Pattern.compile("_hierarchy_(.*?).csv");
        for (File file : genHierFiles) {
            Matcher matcher = pattern.matcher(file.getName());
            if (matcher.find()) {
                CSVHierarchyInput hier = new CSVHierarchyInput(file, StandardCharsets.UTF_8, ';');
                String attributeName = matcher.group(1);
                data.getDefinition().setAttributeType(attributeName, Hierarchy.create(hier.getHierarchy()));
            }
        }

        return data;
    }

    /**
     * Entry point.
     *
     * @param args the arguments
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        double highestRiskThreshold = 0.3;
        boolean aboveHighestRiskThreshold = true;
        int iter = 0;
        int maxIter = 20;
        Data data = createData("adult");
        data.getDefinition().setAttributeType("occupation", AttributeType.SENSITIVE_ATTRIBUTE);
        while (aboveHighestRiskThreshold & iter <= maxIter){
            iter += 1;
            ARXAnonymizer anonymizer = new ARXAnonymizer();
            ARXConfiguration config = ARXConfiguration.create();
            config.addPrivacyModel(new EntropyLDiversity("occupation", iter));
            config.setSuppressionLimit(0.04d);
            config.setQualityModel(Metric.createEntropyMetric());



            // Anonymize
//            analyzeAttributes(data.getHandle());
//            analyzeData(data.getHandle());
            data.getHandle().release();
            ARXResult result = anonymizer.anonymize(data, config);
            double highestRisk = analyzeData(result.getOutput());
            System.out.println("Iteration: " +iter);
            System.out.println("Highest risk: " +highestRisk);
            if (highestRisk < highestRiskThreshold){
                aboveHighestRiskThreshold = false;
                System.out.println("Risk threshold reached");

            }
//            System.out.println("l: " +i);
//            analyzeAttributes(result.getOutput());
//            printResult(result, data);
        }

    }
    /**
     * Perform risk analysis
     * @param handle
     */
    private static void analyzeAttributes(DataHandle handle) {
        ARXPopulationModel populationmodel = ARXPopulationModel.create(ARXPopulationModel.Region.USA);
        RiskEstimateBuilder builder = handle.getRiskEstimator(populationmodel);
        RiskModelAttributes riskmodel = builder.getAttributeRisks();
        for (RiskModelAttributes.QuasiIdentifierRisk risk : riskmodel.getAttributeRisks()) {
            System.out.println("   * Distinction: " + risk.getDistinction() + ", Separation: " + risk.getSeparation() + ", Identifier: " + risk.getIdentifier());
        }
    }

    private static double analyzeData(DataHandle handle) {

        ARXPopulationModel populationmodel = ARXPopulationModel.create(ARXPopulationModel.Region.USA);
        RiskEstimateBuilder builder = handle.getRiskEstimator(populationmodel);
        RiskModelHistogram classes = builder.getEquivalenceClassModel();
        RiskModelSampleRisks sampleReidentifiationRisk = builder.getSampleBasedReidentificationRisk();
        RiskModelSampleUniqueness sampleUniqueness = builder.getSampleBasedUniquenessRisk();
        RiskModelPopulationUniqueness populationUniqueness = builder.getPopulationBasedUniquenessRisk();

        int[] histogram = classes.getHistogram();

        System.out.println("   * Equivalence classes:");
        System.out.println("     - Average size: " + classes.getAvgClassSize());
//        System.out.println("     - Num classes : " + classes.getNumClasses());
//        System.out.println("     - Histogram   :");
//        for (int i = 0; i < histogram.length; i += 2) {
//            System.out.println("        [Size: " + histogram[i] + ", count: " + histogram[i + 1] + "]");
//        }
//        System.out.println("   * Risk estimates:");
//        System.out.println("     - Sample-based measures");
//        System.out.println("       + Average risk     : " + sampleReidentifiationRisk.getAverageRisk());
//        System.out.println("       + Lowest risk      : " + sampleReidentifiationRisk.getLowestRisk());
//        System.out.println("       + Tuples affected  : " + sampleReidentifiationRisk.getFractionOfTuplesAffectedByLowestRisk());
//        System.out.println("       + Highest risk     : " + sampleReidentifiationRisk.getHighestRisk());
//        System.out.println("       + Tuples affected  : " + sampleReidentifiationRisk.getFractionOfTuplesAffectedByHighestRisk());
//        System.out.println("       + Sample uniqueness: " + sampleUniqueness.getFractionOfUniqueTuples());
//        System.out.println("     - Population-based measures");
//        System.out.println("       + Population unqiueness (Zayatz): " + populationUniqueness.getFractionOfUniqueTuples(RiskModelPopulationUniqueness.PopulationUniquenessModel.ZAYATZ));
        return(sampleReidentifiationRisk.getHighestRisk());
    }
}
