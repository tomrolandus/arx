package org.deidentifier.arx.Smooth;

import akka.NotUsed;
import akka.actor.ActorSystem;
import akka.http.javadsl.ConnectHttp;
import akka.http.javadsl.Http;
import akka.http.javadsl.ServerBinding;
import akka.http.javadsl.marshallers.jackson.Jackson;
import akka.http.javadsl.model.HttpRequest;
import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.http.javadsl.server.AllDirectives;
import akka.http.javadsl.server.Route;
import akka.stream.ActorMaterializer;
import akka.stream.javadsl.Flow;
import org.apache.commons.lang.StringUtils;
import org.deidentifier.arx.*;
import org.deidentifier.arx.criteria.KAnonymity;
import org.deidentifier.arx.examples.Example;
import org.deidentifier.arx.io.CSVHierarchyInput;

import org.deidentifier.arx.AttributeType.Hierarchy;
import org.deidentifier.arx.metric.Metric;
import org.deidentifier.arx.risk.RiskEstimateBuilder;
import org.deidentifier.arx.risk.RiskModelAttributes;
import org.json.simple.JSONArray;
import scala.util.parsing.json.JSON;

import java.io.File;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletionStage;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

public class SmoothIO extends AllDirectives {
    private String path;
    private Data data;
    private String dataName;
    private ARXResult result;
    private DataHandle currentDataHandle;
    private ARXPopulationModel populationmodel;
    private ArrayList<SmoothNode> smoothNodes;
    private ArrayList<SmoothNode> recommendations;
    private ArrayList<SmoothNode> appliedRecommendations;

    public ArrayList<SmoothNode> getSmoothNodes() {
        return smoothNodes;
    }

    public void setSmoothNodes(ArrayList<SmoothNode> smoothNodes) {
        this.smoothNodes = smoothNodes;
    }


    public SmoothIO() throws IOException {

    }

    /**
     * This methods load the data from as csv, but does not handle the hierarchy
     *
     * @param filename file name of the data csv
     * @return a Data object
     * @throws IOException
     */
    public void loadDataCsv(final String filename) throws IOException {
        this.dataName = filename;
        this.data = Data.create(path + filename + ".csv", StandardCharsets.UTF_8, ';');
        for (int i = 0; i < data.getHandle().getNumColumns(); i++) {
            data.getDefinition().setAttributeType(data.getHandle().getAttributeName(i), AttributeType.QUASI_IDENTIFYING_ATTRIBUTE);
        }
    }


    /**
     * This method automatically adds the hierarchies to the data if the hierarchies
     * have the format: path/dataName_hierarchy_attributeName.csv
     *
     * @throws IOException
     */
    public void addHierarchiesFromFolder() throws IOException {
        if (path == null || dataName == null) {
            System.out.println("something is null which should not ne");
        }
        // Read generalization hierarchies
        FilenameFilter hierarchyFilter = new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                if (name.matches(dataName + "_hierarchy_(.)+.csv")) {
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
                this.data.getDefinition().setAttributeType(attributeName, Hierarchy.create(hier.getHierarchy()));
            }
        }


    }


    /**
     * Set the path of the folder containing the data and hierarchy files, assumes special naming for future methods
     *
     * @param path
     */
    public void setFolderPath(String path) {
        this.path = path;
    }

    /**
     * returns the path of the folder containing the data and hierarchies csv
     *
     * @return
     */
    public String getFolderPath() {
        return this.path;
    }


    /**
     * Just for testing purposes
     * TODO: remove this method
     */
//    public void printCurrentHandle() {
//        print(this.data.getHandle());
//    }

    /**
     * Calculate Alpha Distinction and Separation
     * TODO: remove this function
     */
    public void analyzeAttributes() {
        DataHandle handle = this.data.getHandle();
        ARXPopulationModel populationmodel = ARXPopulationModel.create(ARXPopulationModel.Region.EUROPEAN_UNION);
        RiskEstimateBuilder builder = handle.getRiskEstimator(populationmodel);
        RiskModelAttributes riskmodel = builder.getAttributeRisks();

        // output
        printPrettyTable(riskmodel.getAttributeRisks());
    }

    /**
     * Helper that prints a table
     * TODO: remove this function
     *
     * @param quasiIdentifiers
     */
    private static void printPrettyTable(RiskModelAttributes.QuasiIdentifierRisk[] quasiIdentifiers) {

        // get char count of longest quasi-identifier
        int charCountLongestQi = quasiIdentifiers[quasiIdentifiers.length - 1].getIdentifier().toString().length();

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
     * "anonymizes" to get an ARXresult object
     *
     * @throws IOException
     */
    public void createResult() throws IOException {
        recommendations = new ArrayList<SmoothNode>();
        populationmodel = ARXPopulationModel.create(data.getHandle().getNumRows(), 0.01d);
        ARXAnonymizer anonymizer = new ARXAnonymizer();
        ARXConfiguration config = ARXConfiguration.create();
        config.addPrivacyModel(new KAnonymity(1));
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
        result = anonymizer.anonymize(data, config);
        currentDataHandle = result.getOutput(result.getLattice().getBottom());
//        showGeneralizations(result.getLattice().getBottom());
//        ArrayList<SmoothNode> nodes = getSuccessorsGeneralizingSameAttribute(0);
        //TODO make this a class var
        makeRecommendations("m", 99);
//        for (SmoothNode n : smoothNodes) {
//            System.out.println(n.toString());
//        }
    }


    /**
     * prints out the generalizations applied to a certain node
     *
     * @param node
     */
    private void showGeneralizations(ARXLattice.ARXNode node) {
        DataHandle temp_handle = this.result.getOutput(node);
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
        for (int i = 0; i < qis.size(); i++) {
            System.out.println("   * " + identifiers[i] + ": " + generalizations[i]);
        }
    }

    /**
     * This methods explore the lattice and returns the nodes generalizing the same attribute
     * in SmoothNode objects which also store the attribute name, index and generalization
     *
     * @param attributeIndex the index of the attribute we want to generalize
     * @return an ArrayList of nodes
     */
    private ArrayList<SmoothNode> getSuccessorsGeneralizingSameAttribute(int attributeIndex, ARXLattice.ARXNode node) {
        if (node == null) {
            node = result.getLattice().getBottom();
        }
        ArrayList<SmoothNode> nodes = new ArrayList<>();
        getSuccessorsGeneralizingSameAttribute(node, attributeIndex, nodes);
        return nodes;
    }


    /**
     * private recursive method for getting the nodes generalizing a same attribute
     *
     * @param node
     * @param attributeIndex
     * @param nodes
     */
    private void getSuccessorsGeneralizingSameAttribute(ARXLattice.ARXNode node, int attributeIndex, ArrayList<SmoothNode> nodes) {
        DataHandle temp_handle = result.getOutput(node);
        node.expand();
        final List<String> qis = new ArrayList<String>(temp_handle.getDefinition().getQuasiIdentifyingAttributes());
        int maxLevelOfAttribute = temp_handle.getDefinition().getHierarchy(qis.get(attributeIndex))[0].length - 1;
        int currentGeneralization = node.getGeneralization(qis.get(attributeIndex));


        ARXLattice.ARXNode[] successors = node.getSuccessors();
        for (ARXLattice.ARXNode successor : successors) {
            if (successor.getGeneralization(qis.get(attributeIndex)) == currentGeneralization + 1) {
                nodes.add(new SmoothNode(successor,
                        getPJMrisks(result.getOutput(successor)),
                        attributeIndex,
                        qis.get(attributeIndex),
                        currentGeneralization + 1,
                        maxLevelOfAttribute));
                getSuccessorsGeneralizingSameAttribute(successor, attributeIndex, nodes);
            }
        }


    }


    /**
     * Get the Prosecutor, Journalist and Marketer risks of a certain node
     *
     * @param handle: the data handle of the node for which you want to get the risks
     * @return
     */
    private double[] getPJMrisks(DataHandle handle) {
        double[] risks = new double[3];
        risks[0] = handle.getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedProsecutorRisk();
        risks[1] = handle.getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedJournalistRisk();
        risks[2] = handle.getRiskEstimator(populationmodel).getSampleBasedReidentificationRisk().getEstimatedMarketerRisk();
        return risks;
    }


    /**
     * Prints an JSONArray to a file
     *
     * @param jsonObjects
     * @param fileName
     */
    private void writeJSONArray(JSONArray jsonObjects, String fileName) {
        try (FileWriter file = new FileWriter(fileName + ".json")) {

            file.write(jsonObjects.toJSONString());
            file.flush();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public JSONArray getRiskJSONArray(){
        //todo javadoc
        JSONArray jarray =  new JSONArray();
        jarray.add(this.currentDataHandle.getRiskEstimator(this.populationmodel).getSampleBasedReidentificationRisk().getMixedRisksJSONObject());
        jarray.addAll(this.currentDataHandle.getRiskEstimator(this.populationmodel).getSampleBasedRiskDistribution().getRiskHistogramValuesJSON());
        return jarray;
    }

    public void writeRisksJSON(String filename, JSONArray jarray){
        writeJSONArray(jarray, filename);
    }


    /**
     * Writes a JSON file with the data of the given node
     *
     * @param node
     * @param filename
     */
    private void writeDataToJSON(ARXLattice.ARXNode node, String filename) {
        if (filename == "") {
            filename = "default";
        }
        result.getOutput(node).writeDataToJSON(filename);
    }

    /**
     * Writes a JSON file with the header (attributes) of the data
     *
     * @param node
     * @param filename
     */
    private void writeHeaderToJSON(ARXLattice.ARXNode node, String filename) {
        if (filename == "") {
            filename = "default";
        }
        result.getOutput(node).writeHeaderToJSON(filename);
    }


    /**
     * get all the risk nodes per attribute (generalized all the way from bottom to top)
     * passing node == null will start the process from the bottom node
     *
     * @return
     */
    public ArrayList<SmoothNode> getAllVerticalGeneralizations(ARXLattice.ARXNode node) {
        ArrayList<SmoothNode> riskNodes = new ArrayList<>();
        final List<String> qis = new ArrayList<String>(result.getOutput().getDefinition().getQuasiIdentifyingAttributes());
        for (int i = 0; i < qis.size(); i++) {
            riskNodes.addAll(getSuccessorsGeneralizingSameAttribute(i, node));
        }
        return riskNodes;
    }


    /**
     * prints all the SmoothNode objects to a JSON. These are not the
     * recommendations yet, but rather all of the items.
     * This function should not be called
     *
     * @param filename
     * @deprecated
     */
    private void writeRecommendationNodesToJSON(String filename) {
        JSONArray riskNodesJSONArray = new JSONArray();
        for (SmoothNode node : this.smoothNodes) {
            riskNodesJSONArray.add(node.getJSONObject());
        }
        try (FileWriter file = new FileWriter(filename + ".json")) {

            file.write(riskNodesJSONArray.toJSONString());
            file.flush();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private void writeAllJSONs() {
        currentDataHandle.writeDataToJSON("data");
        currentDataHandle.writeHeaderToJSON("dataHeader");
//        writeRisksJSON("");
        writeRecommendationsToJSON("recommendations");

        //todo current handle PJM risks to json
        //todo current risk distributions to json
        //todo recommendations to json

    }


    public void applyRecommendation(int hash) {
        SmoothNode node = getSmoothNodeByHashFromRecommendations(hash);
        if (this.appliedRecommendations == null) {
            this.appliedRecommendations = new ArrayList<SmoothNode>();
        }
        this.appliedRecommendations.add(node);
        currentDataHandle = result.getOutput(node.getNode());
//        System.out.println(currentDataHandle.getRiskEstimator(populationmodel).getSampleBasedRiskDistribution());
        makeRecommendations("m", 99);


        //TODO compute new recommendations
        //TODO export new JSONs : Data, risks, recommendations

    }


    /**
     * Find the SmoothNode of the hash in the recommendations
     *
     * @param hash
     * @return
     */
    private SmoothNode getSmoothNodeByHashFromRecommendations(int hash) {
        for (SmoothNode node : this.recommendations) {
            if (node.getHashCode() == hash) {
                return node;
            }
        }

        System.out.println("NODE NOT FOUND BY HASHCODE");
        return null;
    }


    /**
     * get an ArrayList with the recommendations (SmoothNode objects), it does not allow several recs
     * per attribute
     *
     * @param number      number of recommendations, if bigger than number attributes it returns numberOfAttributes recommendations
     * @param pointOfView p for prosecutor, j for Journalist, m for Marketer
     * @return
     */
    public void makeRecommendations(String pointOfView, int number) {
        if (appliedRecommendations == null) {
            appliedRecommendations = new ArrayList<SmoothNode>();
        }
        if (appliedRecommendations.size() > 0) {
//            System.out.println("the current recommendation: " + appliedRecommendations.get(0));
        }
        if (recommendations.size() == 0) {
//            System.out.println("we don't have recommendations yet");
            smoothNodes = getAllVerticalGeneralizations(null);
        } else {
            SmoothNode temp = appliedRecommendations.get(appliedRecommendations.size() - 1);
//            System.out.println("we're starting with this node as rec " + temp);
//            System.out.println("index of rec: " + (appliedRecommendations.size() - 1));
            smoothNodes = getAllVerticalGeneralizations(appliedRecommendations.get(appliedRecommendations.size() - 1).getNode());
        }

        //todo make recommendations (and store) for P,J and M simultaneously
        //todo use metric penalizing for too much generalization
        //todo maybe i should keep the recomendations as class var?
        int povIndex = 2; // marketer
        if (pointOfView.equals("p")) {
            povIndex = 0;
        } else {
            if (pointOfView.equals("j")) {
                povIndex = 1;
            }
        }

        int numberAttributes = result.getOutput().getDefinition().getQuasiIdentifyingAttributes().size();
        if (number > numberAttributes) {
            number = numberAttributes;
        }
        boolean[] attributesUsed = new boolean[numberAttributes];
        ArrayList<SmoothNode> recs = new ArrayList<>();
        for (SmoothNode node : smoothNodes) {

            double mRisk = node.getRisks()[povIndex];
            boolean added = FALSE;
            int i = 0;
            while ((i < number - 1) & (added == FALSE)) { // the number of recommendations we want to have
                if (attributesUsed[node.getAttributeIndex()]) { // we already have a generalization with this attribute
                    for (int j = 0; j < recs.size(); j++) { // find the node that uses the same generalization
                        if (recs.get(j).getAttributeIndex() == node.getAttributeIndex()) { // we found the recommendation with same attribute
                            if (mRisk < recs.get(j).getRisks()[povIndex]) { // the new node has lower risk, we should recommend it
//                                System.out.println("we remove " + recs.get(j));
                                recs.remove(j); // we remove the previous recommendation, the next part will put the new one at right place
                            }
                        }
                    }
                }

                if (i >= recs.size()) { // either we don't have recommendations yet, or not not enough
                    added = TRUE;
//                    System.out.println("i >= recs.size we add " + node);
                    recs.add(node); // the previous loop makes sure it's not from the same attribute
                    attributesUsed[node.getAttributeIndex()] = TRUE;
                } else { // we have enough recommendations already, so we'll remove one
                    if (mRisk < recs.get(i).getRisks()[povIndex]) { // the new node has lower risk so we should add it
                        added = TRUE;
//                        System.out.println("we add " + node);
                        recs.add(i, node); // we're pushing the node inside the AL and thus moving the following values away in the AL
                        attributesUsed[node.getAttributeIndex()] = TRUE;
                        if (recs.size() > number) { // we have too many recommendations
                            attributesUsed[recs.get(number).getAttributeIndex()] = FALSE; // we just pushed this one out so we're not using this attribute anymore
                        }


                    }

                }
                i++;
            }
        }
//        System.out.println(recs.size());
//        for (SmoothNode n : recs) {
//            System.out.println(n.toString());
//        }
//        System.out.println("-----------------");

        ArrayList<SmoothNode> funcOut = new ArrayList<>();
        // We we already have recommendations we might find less new ones
        // hence this block
        if (number > recs.size()) {
            number = recs.size();
        }
        for (int i = 0; i < number; i++) {
            funcOut.add(recs.get(i));
        }

        this.recommendations = funcOut;

    }

    /**
     * calls the method to make the recommendations and returns them
     * the idea is that eventually we don't compute them each time again
     *
     * @return
     */
    public ArrayList<SmoothNode> getRecommendations() {
//        makeRecommendations(pov, number);
        return this.recommendations;
    }


    /**
     * Writes the recommenations to a jason,
     * atm it's hardcoded to get as many recs as possible
     *
     * @param name
     */
    public void writeRecommendationsToJSON(String name) {
        //todo put the risks (PJM and distribution) in a JSONObject (method)
        writeJSONArray(getRecommendationsJSONArray(), name);
    }


    /**
     * get the JSONArray of the recommendations
     *
     * @return
     */
    public JSONArray getRecommendationsJSONArray() {
        ArrayList<SmoothNode> recs = this.recommendations;
        JSONArray jarray = new JSONArray();
        for (SmoothNode node : recs) {
            jarray.add(node.getJSONObject());
        }
        return jarray;
    }

    public void removeRecommendation(int hash) {
        //todo make this method
        // this is not trivial because if you have several recs
        // then removing one that is not the last one means
        // you have to find new nodes that hold the transformations

    }


    public void api() throws Exception {
        // boot up server using the route as defined below
        ActorSystem system = ActorSystem.create("routes");

        final Http http = Http.get(system);
        final ActorMaterializer materializer = ActorMaterializer.create(system);


        final Flow<HttpRequest, HttpResponse, NotUsed> routeFlow = this.appRoute().flow(system, materializer);
        final CompletionStage<ServerBinding> binding = http.bindAndHandle(routeFlow,
                ConnectHttp.toHost("localhost", 8080), materializer);

        System.out.println("Server online at http://localhost:8080/\nPress RETURN to stop...");
        System.in.read(); // let it run until user presses return

        binding
                .thenCompose(ServerBinding::unbind) // trigger unbinding from the port
                .thenAccept(unbound -> system.terminate()); // and shutdown when done
    }

    private Route appRoute() {
        return concat(
                path("hello", () ->
                        get(() ->
//                                complete(StatusCodes.OK, new SmoothNode(11), Jackson.<SmoothNode>marshaller()))));
                                complete(StatusCodes.OK, getRiskJSONArray().toJSONString()))));
    }
}

