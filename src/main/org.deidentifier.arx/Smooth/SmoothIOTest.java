package org.deidentifier.arx.Smooth;

import java.io.IOException;
import java.util.ArrayList;

public class SmoothIOTest {

    public static void main(String[] args) throws Exception {
        SmoothIO smoothio = new SmoothIO();
        smoothio.setFolderPath("data/");
        smoothio.loadDataCsv("adult");
        smoothio.addHierarchiesFromFolder();
        smoothio.createResult();
        smoothio.api();
////        smoothio.printRecommendationNodesToJSON("recommendationNodes");
//        smoothio.writeRecommendationsToJSON("recommendations_initial");
//        ArrayList<SmoothNode> initialRecommendations = smoothio.getRecommendations();
//        smoothio.applyRecommendation(initialRecommendations.get(0).getHashCode());
//        ArrayList<SmoothNode> secondRecommenations = smoothio.getRecommendations();
//        smoothio.applyRecommendation(secondRecommenations.get(0).getHashCode());

    }
}
