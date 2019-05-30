package org.deidentifier.arx.Smooth;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import org.deidentifier.arx.ARXLattice;
import org.json.simple.JSONObject;

public class SmoothNode<node, prosecutorScore, journalistScore, marketerScore> {
    private ARXLattice.ARXNode node;
    private double[] risks;
    private int attributeIndex;
    private String attributeName;
    private int generalizationLevel;
    private int maxLevelAttribute;

    public int getHashCode() {
        return hashCode;
    }

    public void setHashCode(int hashCode) {
        this.hashCode = hashCode;
    }

    private int hashCode;

    public int getAttributeIndex() {
        return attributeIndex;
    }

    public void setAttributeIndex(int attributeIndex) {
        this.attributeIndex = attributeIndex;
    }

    public String getAttributeName() {
        return attributeName;
    }

    public void setAttributeName(String attributeName) {
        this.attributeName = attributeName;
    }

    public int getGeneralizationLevel() {
        return generalizationLevel;
    }

    public void setGeneralizationLevel(int generalizationLevel) {
        this.generalizationLevel = generalizationLevel;
    }


    @JsonCreator
    public SmoothNode(@JsonProperty("node") ARXLattice.ARXNode node,@JsonProperty("risks") double[] risks){
        this.node = node;
        this.risks = risks;
    }


    @JsonCreator
    public SmoothNode(ARXLattice.ARXNode node, @JsonProperty("risks") double[] risks, int attributeIndex, String attributeName, int generalizationLevel, int maxLevel){
        this.node = node;
        this.risks = risks;
        this.attributeIndex = attributeIndex;
        this.attributeName = attributeName;
        this.generalizationLevel = generalizationLevel;
        this.maxLevelAttribute = maxLevel;
        this.hashCode = this.node.hashCode();
    }

    public ARXLattice.ARXNode getNode() {
        return node;
    }

    public void setNode(ARXLattice.ARXNode node) {
        this.node = node;
    }

    public double[] getRisks() {
        return risks;
    }

    public void setRisks(double[] risks) {
        this.risks = risks;
    }

//    public String toString(){
//        return (attributeName +"[" + generalizationLevel +"/"
//                + maxLevelAttribute + "] -> " + "P: "
//                +risks[0] + ", J: " +risks[1] + ", M: " + risks[2]);
//    }

    public JSONObject getJSONObject(){
        JSONObject obj  = new JSONObject();
        obj.put("hashCode", hashCode);
        obj.put("attributeName",attributeName);
        obj.put("attributeIndex", attributeIndex);
        obj.put("level", generalizationLevel);
        obj.put("maxLevel", maxLevelAttribute);
        obj.put("prosecutorRisk", risks[0]);
        obj.put("journalistRisk", risks[1]);
        obj.put("marketerRisk", risks[2]);
        return obj;
    }


}
