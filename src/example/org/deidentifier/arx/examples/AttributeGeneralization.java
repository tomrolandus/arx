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

//import jdk.swing.interop.SwingInterOpUtils;
import org.deidentifier.arx.*;
import org.deidentifier.arx.AttributeType.Hierarchy;
import org.deidentifier.arx.Smooth.SmoothNode;
import org.deidentifier.arx.criteria.KAnonymity;
import org.deidentifier.arx.io.CSVHierarchyInput;
import org.deidentifier.arx.metric.Metric;
import org.deidentifier.arx.risk.*;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * This class implements an example on how to use the l-diversity privacy model
 * without protecting sensitive assocations.
 *
 * @author Fabian Prasser
 * @author Florian Kohlmayer
 */
public class AttributeGeneralization extends Example {

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
        System.out.println(testDir.getName());
        File[] genHierFiles = testDir.listFiles(hierarchyFilter);
        for(File f: genHierFiles){
            System.out.println(f.getName());

        }
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

    /**§
     * Entry point.
     *
     * @param args the arguments
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        Data data = createData("adult");
//        data.getDefinition().setAttributeType("occupation", AttributeType.SENSITIVE_ATTRIBUTE);
//        double initialRisk = analyzeData(data.getHandle());
//        System.out.println("Initial risk: " + initialRisk);


        ARXPopulationModel populationmodel = ARXPopulationModel.create(data.getHandle().getNumRows(), 0.01d);
        ARXAnonymizer anonymizer = new ARXAnonymizer();
        ARXConfiguration config = ARXConfiguration.create();
        config.addPrivacyModel(new KAnonymity(5));
//        config.addPrivacyModel(new EntropyLDiversity("occupation", iter));
//        config.setSuppressionLimit(0.04d);
        config.setQualityModel(Metric.createEntropyMetric());
//
//
//
            // Anonymize
//            analyzeAttributes(data.getHandle());
//            analyzeData(data.getHandle());
//            data.getHandle().release();
        ARXResult result = anonymizer.anonymize(data, config);
//        showGeneralizations(populationmodel,result,result.getGlobalOptimum());
//        result.getOutput(false).save("data/tom_test2.csv", ',');
        ARXLattice.ARXNode bottomNode = result.getLattice().getBottom();
        bottomNode.expand();
        System.out.println(bottomNode.getSuccessors().length);
        // Perform risk analysis
//        System.out.println("- Output data");
////        print(result.getOutput());
//        System.out.println("\n- Mixed risks");
//        System.out.println("  * Prosecutor re-identification risk: " + result.getOutput().getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedProsecutorRisk());
//        System.out.println("  * Journalist re-identification risk: " + result.getOutput().getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedJournalistRisk());
//        System.out.println("  * Marketer re-identification risk: " + result.getOutput().getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedMarketerRisk());
//

//        ARXLattice.ARXNode nodeBottom = result.getLattice().getBottom();
//        nodeBottom.expand();


//        DataHandle temp_handle = result.getOutput(nodeBottom);

//        ARXLattice lattice = result.getLattice();
//        showGeneralizations(populationmodel,result,lattice.getTop());
//        showGeneralizations(populationmodel,result,lattice.getTop().g);
//        showGeneralizations(populationmodel,result,lattice.getTop().getPredecessors()[0]);
//        lattice.render();

//        System.out.println("- Top node");
//        System.out.println("\n- Mixed risks");


//        showGeneralizations(populationmodel,result,nodeBottom);
//        showGeneralizationsSuccessors(populationmodel,result,nodeBottom, 2,0);


//        ArrayList<SmoothNode> listOutput = new ArrayList<>();
//        showGeneralizationsPerLevel(populationmodel,result,nodeBottom,1,0, nodeBottom, listOutput);
//        System.out.println("list output size: " +listOutput.size());



//        ARXLattice.ARXNode[] successors = nodeBottom.getSuccessors();
//        for(int i=0; i < successors.length;i++){
//            showGeneralizations(populationmodel,result, successors[i]);
//        ARXLattice.ARXNode succ = nodeBottom.getSuccessors()[0];
//        succ.expand();
//        ARXLattice.ARXNode age2 = succ.getSuccessors()[8];
//        age2.expand();
//        ARXLattice.ARXNode age1 = succ.getPredecessors()[8];
//        age1.expand();
//        getSuccessorsGeneralizingSameAttribute(populationmodel,result,age1);

//        }





//        System.out.println(nodeBottom.getSuccessors().length);
//        System.out.println(nodeBottom.getPredecessors().length);

        //            System.out.println("l: " +i);
//            analyzeAttributes(result.getOutput());
//            printResult(result, data);

    }

    /**
     * Recursive method to show the generalizations performed and corresponding
     * risk measures by exploring the lattice
     * @param populationmodel
     * @param result
     * @param node
     * @param maxDepth
     * @param currentDepth
     */
    private static void showGeneralizationsSuccessors(ARXPopulationModel populationmodel, ARXResult result, ARXLattice.ARXNode node, int maxDepth, int currentDepth){
        if(currentDepth > maxDepth){
            System.out.println("Max depth reached: " +currentDepth);
            return;
        }
        System.out.println("Current depth: " + currentDepth);
        ARXLattice.ARXNode[] successors = node.getSuccessors();
        System.out.println("Number of successors: " + successors.length);
        ARXLattice.ARXNode[] predecessors = node.getPredecessors();
        System.out.println("Number of predecessors: " + predecessors.length);
            for(int i=0; i < successors.length;i++){
                ARXLattice.ARXNode successor = successors[i];
                successor.expand();
                showGeneralizations(populationmodel,result, successor);
                showGeneralizationsSuccessors(populationmodel,result,successor,maxDepth, currentDepth+1);
            }


    }

    private static void showGeneralizationsPerLevel (ARXPopulationModel populationmodel, ARXResult result, ARXLattice.ARXNode node, int level , int currentDepth, ARXLattice.ARXNode currentNode, ArrayList<SmoothNode> listOutput){
        if(currentDepth > level+1){
//            System.out.println("currentDepth > level+1: " +currentDepth);
            return;
        }
//        System.out.println("Current depth in per level function: " + currentDepth);

        if (currentDepth == level){
            System.out.println("Current depth == level");
            double[] risks = getMixedRisks(populationmodel,result,node);
            SmoothNode currentNodeRisks  = new SmoothNode(node, risks);
            listOutput.add(currentNodeRisks);
            showGeneralizations(populationmodel,result, node);

        }

        if(currentDepth > level){
//            System.out.println("We are above the current level");
            ARXLattice.ARXNode[] predecessors = node.getPredecessors();
//            System.out.println("Number of predecessors: " + predecessors.length);
            for(int i = 0; i < predecessors.length; i++){
                ARXLattice.ARXNode pred = predecessors[i];
                if(!pred.equals(currentNode)){
//                    System.out.println("Predecessor is diff than current node");
                    pred.expand();
                    double[] risks = getMixedRisks(populationmodel,result,pred);
                    SmoothNode currentNodeRisks  = new SmoothNode(pred, risks);
                    listOutput.add(currentNodeRisks);
//                    showGeneralizations(populationmodel,result, pred);

                }else{
                    System.out.println("Pred equals current node");
                }
            }
        }


        ARXLattice.ARXNode[] successors = node.getSuccessors();
        System.out.println("Number of successors: " + successors.length);
        for(int i=0; i < successors.length;i++){
            ARXLattice.ARXNode successor = successors[i];
            successor.expand();
//            showGeneralizations(populationmodel,result, successor);
            showGeneralizationsPerLevel(populationmodel,result,successor,level , currentDepth+1, node, listOutput);
        }
    }

    private static double[] getMixedRisks(ARXPopulationModel populationmodel, ARXResult result, ARXLattice.ARXNode node){
        DataHandle temp_handle = result.getOutput(node);
        RiskModelSampleRisks sampleRisks = temp_handle.getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk();
        double[] risks = {sampleRisks.getEstimatedProsecutorRisk(),sampleRisks.getEstimatedJournalistRisk(),sampleRisks.getEstimatedMarketerRisk()};
        return risks;
    }

    private static void showGeneralizations(ARXPopulationModel populationmodel, ARXResult result, ARXLattice.ARXNode node){
        DataHandle temp_handle = result.getOutput(node);
        System.out.println("");
        System.out.println("  * Prosecutor re-identification risk: " + temp_handle.getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedProsecutorRisk());
        System.out.println("  * Journalist re-identification risk: " + temp_handle.getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedJournalistRisk());
        System.out.println("  * Marketer re-identification risk: " + temp_handle.getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedMarketerRisk());
        final List<String> qis = new ArrayList<String>(temp_handle.getDefinition().getQuasiIdentifyingAttributes());

        // Initialize
        final StringBuffer[] identifiers = new StringBuffer[qis.size()];
        final StringBuffer[] generalizations = new StringBuffer[qis.size()];
        int lengthI = 0;
        int lengthG = 0;
        for (int i = 0; i < qis.size(); i++) {
            identifiers[i] = new StringBuffer();
            generalizations[i] = new StringBuffer();
            identifiers[i].append(qis.get(i));
            generalizations[i].append(node.getGeneralization(qis.get(i)));
            if (temp_handle.getDefinition().isHierarchyAvailable(qis.get(i)))
                generalizations[i].append("/").append(temp_handle.getDefinition().getHierarchy(qis.get(i))[0].length - 1);
            lengthI = Math.max(lengthI, identifiers[i].length());
            lengthG = Math.max(lengthG, generalizations[i].length());
        }

        // Padding
        for (int i = 0; i < qis.size(); i++) {
            while (identifiers[i].length() < lengthI) {
                identifiers[i].append(" ");
            }
            while (generalizations[i].length() < lengthG) {
                generalizations[i].insert(0, " ");
            }
        }

        // Print
        System.out.println(" - Information loss: " + result.getGlobalOptimum().getLowestScore() + " / " + result.getGlobalOptimum().getHighestScore());
        System.out.println(" - Optimal generalization");
        for (int i = 0; i < qis.size(); i++) {
            System.out.println("   * " + identifiers[i] + ": " + generalizations[i]);
        }
    }

    private static void getSuccessorsGeneralizingSameAttribute(ARXPopulationModel populationmodel, ARXResult result, ARXLattice.ARXNode node){
        DataHandle temp_handle = result.getOutput(node);
        showGeneralizations(populationmodel,result,node);
        final List<String> qis = new ArrayList<String>(temp_handle.getDefinition().getQuasiIdentifyingAttributes());

        // Initialize
//        final StringBuffer[] identifiers = new StringBuffer[qis.size()];
        int[] generalizations = new int[qis.size()];
         for (int i = 0; i < qis.size(); i++) {
            generalizations[i] = node.getGeneralization(qis.get(i));
        }
        ARXLattice.ARXNode[] successors = node.getSuccessors();
        System.out.println("successors: " + successors.length);
        System.out.println("Predecessors: " + node.getPredecessors().length);
        for(int i = 0; i < successors.length; i++){
            for (int j = 0; j < qis.size(); j++) {
                System.out.println(generalizations[j]);
                if (generalizations[j] != 0){
                    System.out.println("generalizations[j] != 0" + (generalizations[j] != 0));
                    System.out.println("successors[i].getGeneralization(qis.get(j)) == (generalizations[j] + 1): " + successors[i].getGeneralization(qis.get(j)) + ((generalizations[j] + 1)));
                    if(successors[i].getGeneralization(qis.get(j)) == (generalizations[j] + 1)){
                        System.out.println("we found the successor with same generalization");
                        showGeneralizations(populationmodel,result,successors[i]);
                        //TODO expand
                    }
                }
            }

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


//        System.out.println("   * Equivalence classes:");
//        System.out.println("     - Average size: " + classes.getAvgClassSize());
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
